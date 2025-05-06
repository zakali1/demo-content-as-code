resource "sumologic_cse_match_rule" "sample_match_rule_2" {
  name = "(Sample) CVE-2024-50623 Exploitation Attempt - Cleo"
  enabled = true
  is_prototype = true
  description_expression = "Detects the execution of the \"curl.exe\" command, referencing \"SOCKS\" and \".onion\" domains, which could be indicative of Kalambur backdoor activity."
  expression = "lower(commandLine) like '%/curl.exe%' AND lower(commandLine) like '%/.onion' AND (lower(commandLine) like '%socks5h://%' OR lower(commandLine) like '%socks5://%' OR lower(commandLine) like '%socks4a://%')"
  name_expression = "Kalambur Backdoor Curl TOR SOCKS Proxy Execution"

  entity_selectors {
    entity_type = "_ip"
    expression = "device_ip"
  }

  entity_selectors {
    entity_type = "_username"
    expression = "user_username"
  }

  entity_selectors {
    entity_type = "_hostname"
    expression = "device_hostname"
  }

  severity_mapping {
    type = "constant"
    default = 8
  }

  tags = [
    "_mitreAttackTactic:TA0011",
    "_mitreAttackTechnique:T1573",
    "_mitreAttackTechnique:T1071.001",
    "_mitreAttackTechnique:T1059.001"
  ]
}

resource "sumologic_cse_match_rule" "sample_match_rule_2" {
  name = "(Sample) Kalambur Backdoor Curl TOR SOCKS Proxy Execution"
  enabled = true
  is_prototype = true
  description_expression = "Detects exploitation attempt of Cleo's CVE-2024-50623 by looking for a \"cmd.exe\" process spawning from the Celo software suite with suspicious Powershell commandline."
  expression = "(lower(commandLine) like '%Harmony%' OR lower(commandLine) like '%lexicom%' OR lower(commandLine) like '%VersaLex%' OR lower(commandLine) like '%VLTrader%') AND (lower(commandLine) like '%powershell%' OR lower(commandLine) like '%-enc%' OR lower(commandLine) like '%.Download%')"
  name_expression = "CVE-2024-50623 Exploitation Attempt - Cleo"

  entity_selectors {
    entity_type = "_ip"
    expression = "device_ip"
  }

  entity_selectors {
    entity_type = "_username"
    expression = "user_username"
  }

  entity_selectors {
    entity_type = "_hostname"
    expression = "device_hostname"
  }

  severity_mapping {
    type = "constant"
    default = 8
  }

  tags = [
    "_mitreAttackTactic:TA0002",
    "_mitreAttackTechnique:T1190"
  ]
}

resource "sumologic_cse_aggregation_rule" "sample_aggregation_rule_1" {
  name                   = "(Sample) Okta - Session Anomaly (Multiple ASNs)"
  name_expression        = "Okta - Session Anomaly (Multiple ASNs)"
  description_expression = "This rule detects when a user has utilized multiple distinct ASNs when performing authentication through Okta. This activity could potentially indicate credential theft or a general session anomaly. Examine other Okta related events surrounding the time period for this signal, pivoting off the username value to examine if any other suspicious activity has taken place. If this rule is generating false positives, adjust the threshold value and consider excluding certain user accounts via tuning expression."
  enabled                = true
  is_prototype           = false

  match_expression       = "metadata_vendor = \"Okta\" and metadata_deviceEventId = \"user.authentication.sso\""
  summary_expression     = "{{user_username}} has utilized a number of distinct Autonomous System Numbers (ASNs) which has crossed the threshold (3) value within a 30-minute time period to perform Okta authentication."

  aggregation_functions {
    arguments = [
      "srcDevice_ip_asnNumber",
    ]

    function  = "count_distinct"
    name      = "distinct_asn"
  }

  entity_selectors {
    entity_type = "_username"
    expression  = "user_username"
  }

  severity_mapping {
    default = 1
    type    = "constant"
  }

  tags = [
    "_mitreAttackTactic:TA0001",
    "_mitreAttackTechnique:T1078.004",
  ]

  trigger_expression     = "distinct_asn > 3"
  window_size            = "T30M"

  group_by_entity        = true
  group_by_fields        = []
}

resource "sumologic_cse_chain_rule" "sample_chain_rule_1" {
  name               = "(Sample) Azure DevOps - Agent Pool Created and Deleted within a Short Period"

  description        = <<-EOT
        Context:
        An attacker may create Azure DevOps Agent Pools for malicious activity that are separate from an organization’s pools.

        Detection:
        This detection monitors for the creation and deletion of Agent Pools within 5 days by the same user, with the intent of finding Agent Pools active for short durations.

        Recommended Actions:
        If an alert occurs, investigate the actions taken by the account to determine if this is normal operation of deleting pools or if this suspicious activity.

        Tuning Recommendations:
        If necessary, add a tuning expression for users who frequently create and delete agent pools within the time period specified.
        If necessary, adjust the "within" time period to better represent what is considered a short time period in your organization. Note that 5 days is the maximum time period you can specify for a chain rules.

        Credits:
        This rule is loosely based on the Azure Sentinel ADOAgentPoolCreatedDeleted.yaml detection.
    EOT

  enabled            = true
  group_by_fields    = [
    "changeTarget",
  ]

  is_prototype       = false
  ordered            = true
  summary_expression = "User: {{user_username}}  has created and deleted an agent pool in a short period of time"

  entity_selectors {
    entity_type = "_username"
    expression  = "user_username"
  }

  expressions_and_limits {
    expression = <<-EOT
            metadata_vendor = "Microsoft"
            AND metadata_product = "Azure DevOps Auditing"
            AND metadata_deviceEventId = "AzureDevOpsAuditEvent"
            AND action = "Library.AgentPoolCreated"
        EOT

    limit      = 1
  }

  expressions_and_limits {
    expression = <<-EOT
            metadata_vendor = "Microsoft"
            AND metadata_product = "Azure DevOps Auditing"
            AND metadata_deviceEventId = "AzureDevOpsAuditEvent"
            AND action = "Library.AgentPoolDeleted"
        EOT

    limit      = 1
  }

  tags               = [
    "_mitreAttackTechnique:T1578",
    "_mitreAttackTactic:TA0005",
  ]

  severity           = 3
  window_size        = "T05D"
}

resource "sumologic_cse_threshold_rule" "sample_threshold_rule_1" {
  name               = "(Sample) Password Attack from Host"
  summary_expression = "Password attack from host: {{srcDevice_hostname}}"

  count_distinct     = true
  count_field        = "user_username"
  description        = "Detects multiple failed login attempts from a single source with unique usernames over a 24 hour timeframe. This is designed to catch both slow and quick password spray type attacks. The threshold and time frame can be adjusted based on the customer's environment."
  enabled            = true
  expression         = <<-EOT
        objectType = 'Authentication'
        AND normalizedAction = 'logon'
        AND success = false
        AND NOT
        (
            metadata_deviceEventId = 'Security-4776'
            AND (array_contains(listMatches, 'domain_controllers'))
        )
        AND NOT
        (
            metadata_vendor IN ('Microsoft','Intersect Alliance')
            AND metadata_product IN ('Windows','Snare Enterprise Agent for Windows')
            AND user_username like '%$%'
        )
        AND NOT
        (
            metadata_vendor = 'Microsoft'
            AND metadata_product = 'Azure'
            AND fields['resultType'] = '700082'
        )
        AND NOT array_contains(listMatches, 'vuln_scanners')
        AND
        (
            srcDevice_hostname IS NOT NULL
        )
    EOT

  group_by_fields    = [
    "metadata_vendor",
    "metadata_product",
    "metadata_deviceEventId",
  ]

  is_prototype       = false
  limit              = 10

  entity_selectors {
    entity_type = "_hostname"
    expression  = "srcDevice_hostname"
  }

  tags               = [
    "_mitreAttackTactic:TA0001",
    "_mitreAttackTactic:TA0006",
    "_mitreAttackTechnique:T1110",
    "_mitreAttackTechnique:T1078",
    "_mitreAttackTechnique:T1078.001",
    "_mitreAttackTechnique:T1078.002",
    "_mitreAttackTechnique:T1078.003",
    "_mitreAttackTechnique:T1078.004",
    "_mitreAttackTechnique:T1586",
    "_mitreAttackTechnique:T1586.001",
    "_mitreAttackTechnique:T1586.002",
    "_mitreAttackTactic:TA0008",
    "_mitreAttackTechnique:T1110.003",
    "_mitreAttackTechnique:T1110.002",
    "_mitreAttackTechnique:T1110.001",
  ]

  severity           = 4
  window_size        = "T24H"
}

resource "sumologic_cse_first_seen_rule" "sample_first_seen_rule_1" {
  name                   = "(Sample) Azure DevOps - First Seen Pull Request Policy Bypassed"
  name_expression        = "Azure DevOps - First Seen Pull Request Policy Bypassed"

  baseline_type          = "GLOBAL"
  baseline_window_size   = "2592000000"
  enabled                = true

  description_expression = <<-EOT
        Context:
        An attacker can use pull request bypasses to introduce malicious code into production by circumventing normal review processes.

        Detection:
        This detection monitors for when a user performs a pull request bypass for the first time.

        Tuning Recommendations:
        If there is a known use case for pull request bypasses (emergency updates, lack of available review staff, etc.), add a tuning expression to exclude the user from the detection.

        Recommended Actions:
        Determine whether the pull request bypass was expected.
        Investigate the user who performed the pull request bypass for indications of account compromise or other insider threat activity.

        Credits:
        This detection is based on the Azure Sentinel AzDOHistoricPrPolicyBypassing.yaml rule.
    EOT

  filter_expression      = <<-EOT
        metadata_vendor = "Microsoft"
        AND metadata_product = "Azure DevOps Auditing"
        AND metadata_deviceEventId = "AzureDevOpsAuditEvent"
        AND action = "Git.RefUpdatePoliciesBypassed"
    EOT

  group_by_fields        = []
  is_prototype           = false

  retention_window_size  = "7776000000"
  severity               = 4
  summary_expression     = "User: {{user_username}} has been observed bypassing policy"

  tags                   = [
    "_mitreAttackTechnique:T1098.001",
  ]

  value_fields           = [
    "user_username",
  ]

  entity_selectors {
    entity_type = "_username"
    expression  = "user_username"
  }
}

resource "sumologic_cse_outlier_rule" "sample_outlier_rule_1" {
  name                   = "(Sample) Azure DevOps - Outlier in Pools Deleted Rapidly"
  name_expression        = "Azure DevOps - Outlier in Agent Pools Deleted in an Hour"

  description_expression = <<-EOT
        Context:
        An Attacker with sufficient administrative access to Azure DevOps (ADO) may abuse this access to destroy existing resources by deleting pools.

        Detection:
        This detection identifies statistical outliers in user behavior for the number of pools deleted in an hourly window.

        Recommended Actions:
        If an alert occurs, investigate the actions taken by the account to determine if this is normal operation of deleting pools or if this suspicious activity.

        Tuning Recommendations:
        Determine if the baseline basis should be hourly or daily based on normal activity in your organization.
        If the detection is proving to be too sensitive to the number of pools deleted, adjust the floor value (currently 3) to a number that is less sensitive but within reason. Use Sumo Search using a count and the _timeslice function to aggregate on the number of pools deleted within the hourly (or daily) periods to find what is an acceptable level of activity to not alert on.
    EOT

  enabled                = true

  baseline_window_size   = "2592000000"
  floor_value            = 3
  deviation_threshold    = 3

  group_by_fields        = [
    "user_username",
  ]

  is_prototype           = false
  match_expression       = <<-EOT
        metadata_vendor = "Microsoft"
        AND metadata_product = "Azure DevOps Auditing"
        AND metadata_deviceEventId = "AzureDevOpsAuditEvent"
        AND action = "Library.AgentPoolDeleted"
    EOT

  retention_window_size  = "7776000000"
  window_size            = "T60M"

  severity               = 3
  summary_expression     = "User: {{user_username}} has deleted an abnormal amount of Agent Pools within an hour"

  aggregation_functions {
    arguments = [
      "true",
    ]
    function  = "count"
    name      = "current"
  }

  entity_selectors {
    entity_type = "_username"
    expression  = "user_username"
  }

  tags                   = [
    "_mitreAttackTechnique:T1578.002",
    "_mitreAttackTactic:TA0005",
  ]
}