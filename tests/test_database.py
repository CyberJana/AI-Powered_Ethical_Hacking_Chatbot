from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.database import Base
from database.models import Conversation, Finding, Investigation, Report
from database.repositories import DashboardRepository


def test_dashboard_statistics_reflect_persisted_records() -> None:
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        investigation = Investigation(investigation_id="INV-001", name="Test investigation")
        session.add_all(
            (
                Conversation(title="Test"),
                investigation,
                Finding(investigation=investigation, title="Test finding", severity="high"),
                Report(title="Test report", format="markdown", content="# Test"),
            )
        )
        session.commit()

        stats = DashboardRepository().get_statistics(session)

    assert stats.total_conversations == 1
    assert stats.investigations == 1
    assert stats.findings == 1
    assert stats.high_severity_findings == 1
    assert stats.reports_generated == 1
