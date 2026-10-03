"""Deterministic correlation engine and attack-surface graph builder."""

import uuid
from typing import Dict, Any, List, Optional, Set
from sqlalchemy import select, and_
from sqlalchemy.orm import Session

from backend.app.core.logging import logger
from backend.app.models.investigation import Investigation, ScanRun, Target
from backend.app.models.asset import Asset, Domain, Subdomain, DNSRecord, IPAddress, ASN, IPObservation, ServiceExposure
from backend.app.models.certificate import Certificate, subdomain_certificates
from backend.app.models.technology import Technology, TechnologyVulnerability
from backend.app.models.vulnerability import Vulnerability
from backend.app.models.relationship import AssetRelationship
from backend.app.schemas.graph import GraphNode, GraphEdge, GraphStatistics, GraphResponse


class CorrelationService:
    """
    Deterministic correlation service for building attack-surface relationship graphs.
    Connects: Domain -> Subdomain -> IP -> ASN -> Service -> Technology -> Vulnerability / Certificate.
    Enforces strict ScanRun isolation and idempotent graph edge persistence.
    """

    def correlate_and_persist_asset_relationships(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        scan_run_id: Optional[uuid.UUID],
    ) -> List[AssetRelationship]:
        """
        Extract deterministic asset-to-asset relationships and persist them to AssetRelationship table.
        Idempotent: prevents duplicate rows for the same investigation and scan_run_id.
        Uses optimized batch queries to eliminate N+1 latency.
        """
        persisted_relationships: List[AssetRelationship] = []

        # 1. Fetch existing persisted relationships for this scan_run to avoid duplicates
        existing_query = select(AssetRelationship).where(
            AssetRelationship.investigation_id == investigation_id
        )
        if scan_run_id:
            existing_query = existing_query.where(AssetRelationship.scan_run_id == scan_run_id)
        else:
            existing_query = existing_query.where(AssetRelationship.scan_run_id.is_(None))

        existing_records = db.execute(existing_query).scalars().all()
        existing_keys: Set[str] = {
            f"{r.source_asset_id}_{r.target_asset_id}_{r.relationship_type}"
            for r in existing_records
        }

        # 2. Correlate Domain -> Subdomain (CONTAINS) via joined batch query
        domain_sub_pairs = db.execute(
            select(Domain.asset_id, Subdomain.asset_id, Subdomain.discovery_source)
            .join(Asset, Domain.asset_id == Asset.id)
            .join(Subdomain, Subdomain.domain_id == Domain.id)
            .where(Asset.investigation_id == investigation_id)
        ).all()

        for dom_asset_id, sub_asset_id, disc_source in domain_sub_pairs:
            key = f"{dom_asset_id}_{sub_asset_id}_CONTAINS"
            if key not in existing_keys:
                rel = AssetRelationship(
                    investigation_id=investigation_id,
                    scan_run_id=scan_run_id,
                    source_asset_id=dom_asset_id,
                    target_asset_id=sub_asset_id,
                    relationship_type="CONTAINS",
                    confidence=1.0,
                    attributes={"discovery_source": disc_source},
                )
                db.add(rel)
                persisted_relationships.append(rel)
                existing_keys.add(key)

        # 3. Correlate Subdomain -> IP (RESOLVES_TO) from DNSRecords via joined batch query
        dns_ip_query = (
            select(
                Subdomain.asset_id,
                IPAddress.asset_id,
                DNSRecord.record_type,
                DNSRecord.ttl,
            )
            .join(Asset, Subdomain.asset_id == Asset.id)
            .join(DNSRecord, DNSRecord.subdomain_id == Subdomain.id)
            .join(IPAddress, IPAddress.ip_address == DNSRecord.value)
            .where(
                Asset.investigation_id == investigation_id,
                DNSRecord.record_type.in_(["A", "AAAA"]),
            )
        )
        if scan_run_id:
            dns_ip_query = dns_ip_query.where(DNSRecord.scan_run_id == scan_run_id)

        dns_ip_pairs = db.execute(dns_ip_query).all()
        for sub_asset_id, ip_asset_id, rec_type, ttl in dns_ip_pairs:
            key = f"{sub_asset_id}_{ip_asset_id}_RESOLVES_TO"
            if key not in existing_keys:
                rel = AssetRelationship(
                    investigation_id=investigation_id,
                    scan_run_id=scan_run_id,
                    source_asset_id=sub_asset_id,
                    target_asset_id=ip_asset_id,
                    relationship_type="RESOLVES_TO",
                    confidence=1.0,
                    attributes={"record_type": rec_type, "ttl": ttl},
                )
                db.add(rel)
                persisted_relationships.append(rel)
                existing_keys.add(key)

        if persisted_relationships:
            db.commit()

        return persisted_relationships

    def build_investigation_graph(
        self,
        db: Session,
        investigation_id: uuid.UUID,
        scan_run_id: Optional[uuid.UUID] = None,
        node_types: Optional[List[str]] = None,
        relationship_types: Optional[List[str]] = None,
    ) -> GraphResponse:
        """
        Deterministically construct the full Attack Surface Relationship Graph for an investigation.
        Strictly isolated by ScanRun to ensure historical point-in-time fidelity.
        Optimized with batched indexed queries to eliminate N+1 latency.
        """
        investigation = db.get(Investigation, investigation_id)
        if not investigation:
            raise ValueError(f"Investigation {investigation_id} not found")

        target_domain = investigation.target.primary_domain if investigation.target else "unknown"

        target_scan_run: Optional[ScanRun] = None
        if scan_run_id:
            target_scan_run = db.get(ScanRun, scan_run_id)
            if not target_scan_run or target_scan_run.investigation_id != investigation_id:
                raise ValueError("ScanRun does not belong to the requested investigation")
        else:
            # Fallback to the latest completed or running ScanRun for metadata
            target_scan_run = (
                db.execute(
                    select(ScanRun)
                    .where(ScanRun.investigation_id == investigation_id)
                    .order_by(ScanRun.run_number.desc())
                )
                .scalars()
                .first()
            )

        resolved_scan_run_id = scan_run_id
        scan_run_number = target_scan_run.run_number if target_scan_run else None

        # Ensure asset-to-asset edges are persisted idempotently
        self.correlate_and_persist_asset_relationships(
            db,
            investigation_id,
            scan_run_id or (target_scan_run.id if target_scan_run else None),
        )

        nodes_map: Dict[str, GraphNode] = {}
        edges_map: Dict[str, GraphEdge] = {}

        # -------------------------------------------------------------
        # 1. DOMAINS & SUBDOMAINS (BATCH LOADED)
        # -------------------------------------------------------------
        domain_records = (
            db.execute(
                select(Domain)
                .join(Asset, Domain.asset_id == Asset.id)
                .where(Asset.investigation_id == investigation_id)
            )
            .scalars()
            .all()
        )

        subdomain_records = (
            db.execute(
                select(Subdomain)
                .join(Asset, Subdomain.asset_id == Asset.id)
                .where(Asset.investigation_id == investigation_id)
            )
            .scalars()
            .all()
        )

        subdomains_by_id: Dict[uuid.UUID, Subdomain] = {s.id: s for s in subdomain_records}
        subdomains_by_domain_id: Dict[uuid.UUID, List[Subdomain]] = {}
        for sub in subdomain_records:
            subdomains_by_domain_id.setdefault(sub.domain_id, []).append(sub)

        for dom in domain_records:
            dom_node_id = f"domain:{dom.asset_id}"
            nodes_map[dom_node_id] = GraphNode(
                id=dom_node_id,
                type="domain",
                label=dom.domain_name,
                asset_id=dom.asset_id,
                entity_id=str(dom.id),
                metadata={
                    "domain_name": dom.domain_name,
                    "registrar": dom.registrar,
                    "nameservers": dom.nameservers,
                    "status": dom.status,
                },
            )

            for sub in subdomains_by_domain_id.get(dom.id, []):
                sub_node_id = f"subdomain:{sub.asset_id}"
                nodes_map[sub_node_id] = GraphNode(
                    id=sub_node_id,
                    type="subdomain",
                    label=sub.subdomain_name,
                    asset_id=sub.asset_id,
                    entity_id=str(sub.id),
                    metadata={
                        "subdomain_name": sub.subdomain_name,
                        "is_resolving": sub.is_resolving,
                        "discovery_source": sub.discovery_source,
                    },
                )

                # Edge: Domain -> Subdomain (CONTAINS)
                edge_id = f"edge:{dom_node_id}->{sub_node_id}:CONTAINS"
                edges_map[edge_id] = GraphEdge(
                    id=edge_id,
                    source=dom_node_id,
                    target=sub_node_id,
                    relationship_type="CONTAINS",
                    scan_run_id=resolved_scan_run_id,
                    confidence=1.0,
                    attributes={"discovery_source": sub.discovery_source},
                )

        # -------------------------------------------------------------
        # 2. DNS OBSERVATIONS (SUBDOMAIN -> IP) (BATCH JOINED)
        # -------------------------------------------------------------
        dns_query = (
            select(DNSRecord, IPAddress)
            .join(Subdomain, DNSRecord.subdomain_id == Subdomain.id)
            .join(Asset, Subdomain.asset_id == Asset.id)
            .join(IPAddress, IPAddress.ip_address == DNSRecord.value)
            .where(
                Asset.investigation_id == investigation_id,
                DNSRecord.record_type.in_(["A", "AAAA"]),
            )
        )
        if resolved_scan_run_id:
            dns_query = dns_query.where(DNSRecord.scan_run_id == resolved_scan_run_id)

        observed_dns_ip_rows = db.execute(dns_query).all()
        for dns_rec, ip_record in observed_dns_ip_rows:
            sub = subdomains_by_id.get(dns_rec.subdomain_id)
            if not sub:
                continue

            sub_node_id = f"subdomain:{sub.asset_id}"
            ip_node_id = f"ip:{ip_record.asset_id}"

            if ip_node_id not in nodes_map:
                nodes_map[ip_node_id] = GraphNode(
                    id=ip_node_id,
                    type="ip",
                    label=ip_record.ip_address,
                    asset_id=ip_record.asset_id,
                    entity_id=str(ip_record.id),
                    metadata={
                        "ip_address": ip_record.ip_address,
                        "ip_version": ip_record.ip_version,
                        "reverse_dns": ip_record.reverse_dns,
                        "country": ip_record.country,
                        "organization": ip_record.organization,
                    },
                )

            edge_id = f"edge:{sub_node_id}->{ip_node_id}:RESOLVES_TO"
            edges_map[edge_id] = GraphEdge(
                id=edge_id,
                source=sub_node_id,
                target=ip_node_id,
                relationship_type="RESOLVES_TO",
                scan_run_id=resolved_scan_run_id,
                confidence=1.0,
                attributes={
                    "record_type": dns_rec.record_type,
                    "ttl": dns_rec.ttl,
                    "resolver": dns_rec.resolver,
                },
            )

        # -------------------------------------------------------------
        # 3. IP ROUTING / ASN OBSERVATIONS (IP -> ASN) (BATCH JOINED)
        # -------------------------------------------------------------
        # Priority 1: Check IPObservations for the scan run
        ip_obs_query = (
            select(IPObservation, IPAddress, ASN)
            .join(IPAddress, IPObservation.ip_address_id == IPAddress.id)
            .join(ASN, IPObservation.asn_id == ASN.id)
        )
        if resolved_scan_run_id:
            ip_obs_query = ip_obs_query.where(IPObservation.scan_run_id == resolved_scan_run_id)

        ip_obs_rows = db.execute(ip_obs_query).all()
        observed_ip_ids_with_asn: Set[uuid.UUID] = set()

        for ip_obs, ip_rec, asn_rec in ip_obs_rows:
            ip_node_id = f"ip:{ip_rec.asset_id}"
            if ip_node_id in nodes_map and asn_rec:
                asn_node_id = f"asn:{asn_rec.id}"
                if asn_node_id not in nodes_map:
                    nodes_map[asn_node_id] = GraphNode(
                        id=asn_node_id,
                        type="asn",
                        label=f"AS{asn_rec.asn_number} ({asn_rec.name})",
                        entity_id=str(asn_rec.id),
                        metadata={
                            "asn_number": asn_rec.asn_number,
                            "name": asn_rec.name,
                            "country": asn_rec.country,
                            "allocated_prefix": asn_rec.allocated_prefix,
                        },
                    )

                edge_id = f"edge:{ip_node_id}->{asn_node_id}:ANNOUNCED_BY"
                edges_map[edge_id] = GraphEdge(
                    id=edge_id,
                    source=ip_node_id,
                    target=asn_node_id,
                    relationship_type="ANNOUNCED_BY",
                    scan_run_id=resolved_scan_run_id,
                    confidence=1.0,
                    attributes={
                        "asn_number": asn_rec.asn_number,
                        "prefix": asn_rec.allocated_prefix,
                    },
                )
                observed_ip_ids_with_asn.add(ip_rec.id)

        # Priority 2: Fallback to IPAddress.asn_id for any IP nodes in the graph not yet connected
        ip_nodes_in_graph = [
            node for node in nodes_map.values()
            if node.type == "ip" and node.asset_id
        ]
        if ip_nodes_in_graph:
            ip_asset_ids = [n.asset_id for n in ip_nodes_in_graph]
            fallback_rows = db.execute(
                select(IPAddress, ASN)
                .join(ASN, IPAddress.asn_id == ASN.id)
                .where(IPAddress.asset_id.in_(ip_asset_ids))
            ).all()
            for ip_rec, asn_rec in fallback_rows:
                if ip_rec.id not in observed_ip_ids_with_asn and asn_rec:
                    ip_node_id = f"ip:{ip_rec.asset_id}"
                    asn_node_id = f"asn:{asn_rec.id}"
                    if asn_node_id not in nodes_map:
                        nodes_map[asn_node_id] = GraphNode(
                            id=asn_node_id,
                            type="asn",
                            label=f"AS{asn_rec.asn_number} ({asn_rec.name})",
                            entity_id=str(asn_rec.id),
                            metadata={
                                "asn_number": asn_rec.asn_number,
                                "name": asn_rec.name,
                                "country": asn_rec.country,
                                "allocated_prefix": asn_rec.allocated_prefix,
                            },
                        )

                    edge_id = f"edge:{ip_node_id}->{asn_node_id}:ANNOUNCED_BY"
                    edges_map[edge_id] = GraphEdge(
                        id=edge_id,
                        source=ip_node_id,
                        target=asn_node_id,
                        relationship_type="ANNOUNCED_BY",
                        scan_run_id=resolved_scan_run_id,
                        confidence=1.0,
                        attributes={
                            "asn_number": asn_rec.asn_number,
                            "prefix": asn_rec.allocated_prefix,
                        },
                    )

        # -------------------------------------------------------------
        # 4. SERVICE EXPOSURES (SUBDOMAIN -> SERVICE)
        # -------------------------------------------------------------
        service_query = (
            select(ServiceExposure)
            .join(Asset, ServiceExposure.asset_id == Asset.id)
            .where(Asset.investigation_id == investigation_id)
        )
        if resolved_scan_run_id:
            service_query = service_query.where(ServiceExposure.scan_run_id == resolved_scan_run_id)

        service_records = db.execute(service_query).scalars().all()
        for svc in service_records:
            parent_node_id = f"subdomain:{svc.asset_id}"
            if parent_node_id not in nodes_map:
                parent_node_id = f"domain:{svc.asset_id}"

            svc_node_id = f"service:{svc.id}"
            nodes_map[svc_node_id] = GraphNode(
                id=svc_node_id,
                type="service",
                label=f"{svc.service_name} ({svc.port}/{svc.protocol})",
                asset_id=svc.asset_id,
                entity_id=str(svc.id),
                metadata={
                    "port": svc.port,
                    "protocol": svc.protocol,
                    "service_name": svc.service_name,
                    "http_status": svc.http_status,
                    "page_title": svc.page_title,
                    "tls_version": svc.tls_version,
                    "security_headers": svc.security_headers,
                },
            )

            if parent_node_id in nodes_map:
                edge_id = f"edge:{parent_node_id}->{svc_node_id}:EXPOSES"
                edges_map[edge_id] = GraphEdge(
                    id=edge_id,
                    source=parent_node_id,
                    target=svc_node_id,
                    relationship_type="EXPOSES",
                    scan_run_id=resolved_scan_run_id,
                    confidence=1.0,
                    attributes={
                        "port": svc.port,
                        "protocol": svc.protocol,
                        "service_name": svc.service_name,
                    },
                )

        # -------------------------------------------------------------
        # 5. TECHNOLOGIES (SUBDOMAIN / SERVICE -> TECHNOLOGY)
        # -------------------------------------------------------------
        tech_query = (
            select(Technology)
            .join(Asset, Technology.asset_id == Asset.id)
            .where(Asset.investigation_id == investigation_id)
        )
        if resolved_scan_run_id:
            tech_query = tech_query.where(Technology.scan_run_id == resolved_scan_run_id)

        tech_records = db.execute(tech_query).scalars().all()
        tech_by_id = {t.id: t for t in tech_records}

        for tech in tech_records:
            tech_node_id = f"technology:{tech.id}"
            nodes_map[tech_node_id] = GraphNode(
                id=tech_node_id,
                type="technology",
                label=f"{tech.name} {tech.version or ''}".strip(),
                asset_id=tech.asset_id,
                entity_id=str(tech.id),
                metadata={
                    "name": tech.name,
                    "version": tech.version,
                    "cpe": tech.cpe,
                    "category": tech.category,
                    "confidence": tech.confidence,
                    "evidence_source": tech.evidence_source,
                },
            )

            parent_node_id = f"subdomain:{tech.asset_id}"
            if tech.service_id and f"service:{tech.service_id}" in nodes_map:
                parent_node_id = f"service:{tech.service_id}"
            elif parent_node_id not in nodes_map:
                parent_node_id = f"domain:{tech.asset_id}"

            if parent_node_id in nodes_map:
                edge_id = f"edge:{parent_node_id}->{tech_node_id}:USES_TECHNOLOGY"
                edges_map[edge_id] = GraphEdge(
                    id=edge_id,
                    source=parent_node_id,
                    target=tech_node_id,
                    relationship_type="USES_TECHNOLOGY",
                    scan_run_id=resolved_scan_run_id,
                    confidence=tech.confidence,
                    attributes={
                        "name": tech.name,
                        "version": tech.version,
                        "cpe": tech.cpe,
                        "category": tech.category,
                    },
                )

        # -------------------------------------------------------------
        # 6. VULNERABILITIES (TECHNOLOGY -> VULNERABILITY) (BATCH JOINED)
        # -------------------------------------------------------------
        if tech_by_id:
            tv_rows = db.execute(
                select(TechnologyVulnerability, Vulnerability)
                .join(Vulnerability, TechnologyVulnerability.vulnerability_id == Vulnerability.id)
                .where(TechnologyVulnerability.technology_id.in_(list(tech_by_id.keys())))
            ).all()

            for tv, vuln in tv_rows:
                tech_node_id = f"technology:{tv.technology_id}"
                vuln_node_id = f"vulnerability:{vuln.cve_id}"

                if vuln_node_id not in nodes_map:
                    nodes_map[vuln_node_id] = GraphNode(
                        id=vuln_node_id,
                        type="vulnerability",
                        label=vuln.cve_id,
                        entity_id=str(vuln.id),
                        metadata={
                            "cve_id": vuln.cve_id,
                            "title": vuln.title,
                            "severity": vuln.severity,
                            "cvss_v3_score": vuln.cvss_v3_score,
                            "cvss_vector": vuln.cvss_vector,
                            "verification_status": tv.verification_status,
                            "match_confidence": tv.match_confidence,
                            "source": vuln.source,
                        },
                    )

                edge_id = f"edge:{tech_node_id}->{vuln_node_id}:AFFECTED_BY"
                edges_map[edge_id] = GraphEdge(
                    id=edge_id,
                    source=tech_node_id,
                    target=vuln_node_id,
                    relationship_type="AFFECTED_BY",
                    scan_run_id=resolved_scan_run_id,
                    confidence=tv.match_confidence,
                    attributes={
                        "cve_id": vuln.cve_id,
                        "severity": vuln.severity,
                        "verification_status": tv.verification_status,
                        "match_confidence": tv.match_confidence,
                    },
                )

        # -------------------------------------------------------------
        # 7. CERTIFICATES (SUBDOMAIN -> CERTIFICATE) (BATCH JOINED)
        # -------------------------------------------------------------
        cert_query = (
            select(subdomain_certificates.c.subdomain_id, Certificate)
            .join(Certificate, subdomain_certificates.c.certificate_id == Certificate.id)
            .join(Subdomain, subdomain_certificates.c.subdomain_id == Subdomain.id)
            .join(Asset, Subdomain.asset_id == Asset.id)
            .where(Asset.investigation_id == investigation_id)
        )
        if resolved_scan_run_id:
            cert_query = cert_query.where(
                subdomain_certificates.c.scan_run_id == resolved_scan_run_id
            )

        cert_associations = db.execute(cert_query).all()
        for sub_id, cert in cert_associations:
            sub = subdomains_by_id.get(sub_id)
            if not sub:
                continue

            sub_node_id = f"subdomain:{sub.asset_id}"
            if sub_node_id in nodes_map:
                cert_node_id = f"certificate:{cert.id}"
                if cert_node_id not in nodes_map:
                    nodes_map[cert_node_id] = GraphNode(
                        id=cert_node_id,
                        type="certificate",
                        label=f"CN={cert.subject_cn}",
                        entity_id=str(cert.id),
                        metadata={
                            "fingerprint_sha256": cert.fingerprint_sha256,
                            "subject_cn": cert.subject_cn,
                            "issuer": cert.issuer,
                            "valid_from": str(cert.valid_from),
                            "valid_to": str(cert.valid_to),
                            "is_expired": cert.is_expired,
                            "san_list": cert.san_list,
                        },
                    )

                edge_id = f"edge:{sub_node_id}->{cert_node_id}:HAS_CERTIFICATE"
                edges_map[edge_id] = GraphEdge(
                    id=edge_id,
                    source=sub_node_id,
                    target=cert_node_id,
                    relationship_type="HAS_CERTIFICATE",
                    scan_run_id=resolved_scan_run_id,
                    confidence=1.0,
                    attributes={
                        "subject_cn": cert.subject_cn,
                        "issuer": cert.issuer,
                        "is_expired": cert.is_expired,
                    },
                )

        # -------------------------------------------------------------
        # FILTERING & STATISTICS
        # -------------------------------------------------------------
        final_nodes = list(nodes_map.values())
        final_edges = list(edges_map.values())

        # Apply node_types filter if provided
        if node_types:
            normalized_node_types = {nt.lower().strip() for nt in node_types}
            final_nodes = [n for n in final_nodes if n.type.lower() in normalized_node_types]
            active_node_ids = {n.id for n in final_nodes}
            if len(normalized_node_types) == 1:
                # For single node type (e.g. ASN or IP), retain incident edges connecting to this node type
                final_edges = [
                    e for e in final_edges
                    if e.source in active_node_ids or e.target in active_node_ids
                ]
            else:
                final_edges = [
                    e for e in final_edges
                    if e.source in active_node_ids and e.target in active_node_ids
                ]

        # Apply relationship_types filter if provided
        if relationship_types:
            normalized_rel_types = {rt.upper().strip() for rt in relationship_types}
            final_edges = [
                e for e in final_edges
                if e.relationship_type.upper() in normalized_rel_types
            ]
            if node_types is None:
                connected_node_ids = {e.source for e in final_edges} | {e.target for e in final_edges}
                final_nodes = [n for n in final_nodes if n.id in connected_node_ids]

        # Compute statistics
        nodes_by_type: Dict[str, int] = {}
        for n in final_nodes:
            nodes_by_type[n.type] = nodes_by_type.get(n.type, 0) + 1

        edges_by_type: Dict[str, int] = {}
        for e in final_edges:
            edges_by_type[e.relationship_type] = edges_by_type.get(e.relationship_type, 0) + 1

        stats = GraphStatistics(
            node_count=len(final_nodes),
            edge_count=len(final_edges),
            nodes_by_type=nodes_by_type,
            edges_by_type=edges_by_type,
        )

        return GraphResponse(
            investigation_id=investigation_id,
            scan_run_id=scan_run_id or (target_scan_run.id if target_scan_run else None),
            scan_run_number=scan_run_number,
            target_domain=target_domain,
            nodes=final_nodes,
            edges=final_edges,
            statistics=stats,
        )
