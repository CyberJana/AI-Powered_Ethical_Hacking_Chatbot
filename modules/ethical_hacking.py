"""Curated, non-operational cybersecurity learning topics."""

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class LearningTopic:
    slug: str
    category: str
    title: str
    definition: str
    objective: str
    theory: str
    authorized_lab_example: str
    detection_methodology: str
    mitigation: str
    interview_questions: tuple[str, ...]
    practice_questions: tuple[str, ...]


TOPICS = (
    LearningTopic(
        slug="reconnaissance",
        category="Reconnaissance",
        title="Reconnaissance fundamentals",
        definition="Reconnaissance is the authorized collection of information needed to understand an assessment scope.",
        objective="Establish an accurate, approved asset inventory before testing.",
        theory="Good reconnaissance reduces blind spots and distinguishes owned assets from third-party infrastructure.",
        authorized_lab_example="Compare a supplied CTF asset list with its documented DNS records; do not query systems outside scope.",
        detection_methodology="Review DNS, web, and asset-management logs for unexpected discovery activity.",
        mitigation="Maintain current inventories, minimize public metadata, and alert on unusual lookup patterns.",
        interview_questions=("What is the difference between passive and active reconnaissance?",),
        practice_questions=("Which approval details should be confirmed before reviewing an asset inventory?",),
    ),
    LearningTopic(
        slug="enumeration",
        category="Enumeration",
        title="Service enumeration",
        definition="Enumeration identifies exposed services and their intended security boundaries in an approved environment.",
        objective="Understand exposed attack surface so owners can validate hardening.",
        theory="Service names and versions must be interpreted with configuration, ownership, and exposure context.",
        authorized_lab_example="Interpret a provided scanner report from an isolated training target.",
        detection_methodology="Correlate firewall, IDS, and service logs for repeated connection attempts.",
        mitigation="Remove unnecessary services, enforce network segmentation, and patch supported services.",
        interview_questions=("Why is an open port not automatically a vulnerability?",),
        practice_questions=("What evidence would confirm a service is intentionally exposed?",),
    ),
    LearningTopic(
        slug="web-security",
        category="Web security",
        title="Web application security",
        definition="Web security protects applications, APIs, sessions, and browser interactions from misuse.",
        objective="Prevent common flaws such as injection, broken access control, and unsafe output handling.",
        theory="Trust boundaries occur at every request, identity decision, and data rendering step.",
        authorized_lab_example="Use intentionally vulnerable sample code to identify where parameterized queries are needed.",
        detection_methodology="Review application telemetry, WAF events, code scanning findings, and authentication failures.",
        mitigation="Use parameterized queries, contextual output encoding, least privilege, and security testing in CI.",
        interview_questions=("How do authentication and authorization differ?",),
        practice_questions=("Which control most directly prevents SQL injection in application code?",),
    ),
    LearningTopic(
        slug="network-security",
        category="Network security",
        title="Network segmentation",
        definition="Network segmentation limits communication paths between systems based on business need.",
        objective="Contain incidents and reduce the impact of compromised endpoints.",
        theory="Segmentation combines routing, firewall policy, identity-aware controls, and continuous validation.",
        authorized_lab_example="Review a fictional network diagram and propose least-privilege communication rules.",
        detection_methodology="Monitor denied connections, east-west traffic, and policy changes.",
        mitigation="Default-deny sensitive paths, document dependencies, and regularly validate rules.",
        interview_questions=("How does segmentation support incident containment?",),
        practice_questions=("What information is needed before creating a firewall rule?",),
    ),
    LearningTopic(
        slug="authentication-security",
        category="Authentication security",
        title="Authentication security",
        definition="Authentication establishes an identity before access decisions are made.",
        objective="Reduce account compromise and prevent unauthorized session use.",
        theory="Strong authentication combines secure credential storage, MFA, session protections, and monitoring.",
        authorized_lab_example="Review a sample login flow for rate limiting, MFA, and session-expiry controls.",
        detection_methodology="Investigate repeated failures, impossible travel, and unusual session creation patterns.",
        mitigation="Require phishing-resistant MFA where possible, rate limit attempts, and protect session tokens.",
        interview_questions=("Why should passwords be stored with a modern password-hashing algorithm?",),
        practice_questions=("Which logs help identify a password-spraying attempt?",),
    ),
    LearningTopic(
        slug="defensive-security",
        category="Defensive security",
        title="Defensive monitoring",
        definition="Defensive monitoring uses reliable telemetry to identify, investigate, and contain threats.",
        objective="Produce actionable alerts while preserving evidence and reducing noise.",
        theory="Detection quality depends on baselines, context, data retention, and incident-response playbooks.",
        authorized_lab_example="Classify a sanitized set of authentication events by severity and investigation priority.",
        detection_methodology="Use normalized logs, baselines, and corroborating signals rather than a single event.",
        mitigation="Centralize logging, protect log integrity, and test response procedures.",
        interview_questions=("Why is a baseline useful when investigating anomalies?",),
        practice_questions=("What evidence should accompany a high-confidence alert?",),
    ),
)


def list_topics() -> tuple[LearningTopic, ...]:
    """Return the complete curated catalogue."""
    return TOPICS


def get_topic(slug: str) -> LearningTopic:
    """Return a topic by stable UI/API identifier."""
    for topic in TOPICS:
        if topic.slug == slug:
            return topic
    raise LookupError(f"Learning topic '{slug}' was not found.")
