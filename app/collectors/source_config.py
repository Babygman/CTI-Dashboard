from dataclasses import asdict, dataclass


MSRC_UPDATES_URL = "https://api.msrc.microsoft.com/cvrf/v3.0/updates"
JPCERT_RSS_URL = "https://www.jpcert.or.jp/rss/jpcert.rdf"


@dataclass(frozen=True)
class SourceDefinition:
    source_name: str
    source_type: str
    base_url: str
    feed_url: str | None = None
    cli_name: str | None = None

    def seed_values(self):
        values = asdict(self)
        return {
            "SourceName": values["source_name"],
            "SourceType": values["source_type"],
            "BaseUrl": values["base_url"],
            "FeedUrl": values["feed_url"],
        }


SOURCE_DEFINITIONS = (
    SourceDefinition(
        source_name="CISA KEV",
        source_type="CisaKev",
        base_url="https://www.cisa.gov",
        feed_url=(
            "https://www.cisa.gov/sites/default/files/feeds/"
            "known_exploited_vulnerabilities.json"
        ),
        cli_name="cisa-kev",
    ),
    SourceDefinition(
        source_name="NVD",
        source_type="Nvd",
        base_url="https://nvd.nist.gov",
        feed_url=(
            "https://nvd.nist.gov/feeds/json/cve/2.0/"
            "nvdcve-2.0-modified.json.gz"
        ),
        cli_name="nvd",
    ),
    SourceDefinition(
        source_name="Microsoft Security Response Center",
        source_type="MicrosoftMsrc",
        base_url="https://msrc.microsoft.com",
        feed_url=MSRC_UPDATES_URL,
        cli_name="microsoft-msrc",
    ),
    SourceDefinition(
        source_name="JPCERT",
        source_type="Jpcert",
        base_url="https://www.jpcert.or.jp",
        feed_url=JPCERT_RSS_URL,
        cli_name="jpcert",
    ),
    SourceDefinition(
        source_name="Fortinet PSIRT",
        source_type="Fortinet",
        base_url="https://www.fortiguard.com",
    ),
    SourceDefinition(
        source_name="Cisco Security Advisories",
        source_type="Cisco",
        base_url="https://sec.cloudapps.cisco.com",
    ),
    SourceDefinition(
        source_name="Veeam Security Advisories",
        source_type="Veeam",
        base_url="https://www.veeam.com",
    ),
    SourceDefinition(
        source_name="Broadcom VMware Advisories",
        source_type="Broadcom",
        base_url="https://support.broadcom.com",
    ),
)


RUNNABLE_SOURCE_TYPES = {
    definition.cli_name: definition.source_type
    for definition in SOURCE_DEFINITIONS
    if definition.cli_name
}

DEFAULT_FEED_URLS = {
    definition.source_type: definition.feed_url
    for definition in SOURCE_DEFINITIONS
    if definition.feed_url
}
