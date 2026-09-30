"""
SOC Case Management Engine for UniGuard AI
Inspired by Security Onion Cases.
Allows analysts to escalate alerts and correlate assets into formal forensic investigations.
"""

import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.models.database import Case, Alert, FlowRecord

class CaseManager:
    def create_case(
        self,
        db: Session,
        title: str,
        description: str = "",
        severity: str = "MEDIUM",
        related_alerts: Optional[List[str]] = None,
        related_assets: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        initial_note: Optional[str] = None
    ) -> Case:
        count = db.query(Case).count()
        case_id = f"CASE-{datetime.now().year}-{count + 1:03d}"
        
        now = datetime.now(timezone.utc)
        notes = []
        if initial_note:
            notes.append({
                "timestamp": now.isoformat(),
                "author": "Analyst",
                "note": initial_note
            })

        # Infer related assets from related alerts if not provided
        assets = list(related_assets or [])
        if related_alerts:
            alerts_records = db.query(Alert).filter(Alert.alert_id.in_(related_alerts)).all()
            for a in alerts_records:
                if a.src_ip and a.src_ip not in assets:
                    assets.append(a.src_ip)
                if a.dst_ip and a.dst_ip not in assets:
                    assets.append(a.dst_ip)
                # Auto update alert status to INVESTIGATING
                a.status = "INVESTIGATING"

        new_case = Case(
            case_id=case_id,
            title=title,
            description=description,
            status="OPEN",
            severity=severity,
            created_at=now,
            updated_at=now,
            related_alerts=list(related_alerts or []),
            related_assets=assets,
            analyst_notes=notes,
            tags=list(tags or ["SIH26145", "Triage"])
        )
        db.add(new_case)
        db.commit()
        db.refresh(new_case)
        return new_case

    def get_cases(self, db: Session, limit: int = 50) -> List[Dict[str, Any]]:
        cases = db.query(Case).order_by(desc(Case.id)).limit(limit).all()
        results = []
        for c in cases:
            results.append({
                "id": c.id,
                "case_id": c.case_id,
                "title": c.title,
                "description": c.description,
                "status": c.status,
                "severity": c.severity,
                "created_at": c.created_at.isoformat() if c.created_at else "",
                "updated_at": c.updated_at.isoformat() if c.updated_at else "",
                "related_alerts": c.related_alerts or [],
                "related_assets": c.related_assets or [],
                "analyst_notes": c.analyst_notes or [],
                "tags": c.tags or []
            })
        return results

    def get_case_detail(self, db: Session, case_id: str) -> Optional[Dict[str, Any]]:
        c = db.query(Case).filter(Case.case_id == case_id).first()
        if not c:
            return None

        # Fetch detailed alerts
        detailed_alerts = []
        if c.related_alerts:
            detailed_alerts = db.query(Alert).filter(Alert.alert_id.in_(c.related_alerts)).all()

        return {
            "case": {
                "id": c.id,
                "case_id": c.case_id,
                "title": c.title,
                "description": c.description,
                "status": c.status,
                "severity": c.severity,
                "created_at": c.created_at.isoformat() if c.created_at else "",
                "updated_at": c.updated_at.isoformat() if c.updated_at else "",
                "related_alerts": c.related_alerts or [],
                "related_assets": c.related_assets or [],
                "analyst_notes": c.analyst_notes or [],
                "tags": c.tags or []
            },
            "alerts": detailed_alerts
        }

    def update_case(
        self,
        db: Session,
        case_id: str,
        title: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
        severity: Optional[str] = None,
        tags: Optional[List[str]] = None,
        new_note: Optional[str] = None,
        add_alerts: Optional[List[str]] = None,
        remove_alerts: Optional[List[str]] = None
    ) -> Optional[Case]:
        c = db.query(Case).filter(Case.case_id == case_id).first()
        if not c:
            return None

        now = datetime.now(timezone.utc)
        c.updated_at = now

        if title is not None:
            c.title = title
        if description is not None:
            c.description = description
        if status is not None:
            c.status = status
            if status == "CLOSED":
                # Mark related alerts as RESOLVED
                if c.related_alerts:
                    for a in db.query(Alert).filter(Alert.alert_id.in_(c.related_alerts)).all():
                        a.status = "RESOLVED"
        if severity is not None:
            c.severity = severity
        if tags is not None:
            c.tags = tags

        if new_note:
            notes = list(c.analyst_notes or [])
            notes.append({
                "timestamp": now.isoformat(),
                "author": "Analyst",
                "note": new_note
            })
            c.analyst_notes = notes

        current_alerts = list(c.related_alerts or [])
        if add_alerts:
            for aid in add_alerts:
                if aid not in current_alerts:
                    current_alerts.append(aid)
        if remove_alerts:
            current_alerts = [aid for aid in current_alerts if aid not in remove_alerts]
        c.related_alerts = current_alerts

        db.commit()
        db.refresh(c)
        return c

case_manager = CaseManager()
