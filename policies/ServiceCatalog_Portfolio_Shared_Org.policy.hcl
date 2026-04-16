# LIMITATION: This policy validates aws_servicecatalog_portfolio_share resources directly,
# but cannot trace configuration-level references between portfolio_share and portfolio resources.
# The original Sentinel policy checks which portfolios have NO compliant shares by navigating
# references, but TF Policy can only validate portfolio_share resources individually.
# This means we validate each share independently rather than validating at the portfolio level.

policy {}

# Service Catalog Portfolio Sharing with Organization
#
# This policy enforces that Service Catalog portfolios are shared with organizations
# rather than individual accounts, following AWS Security Hub control ServiceCatalog.1.
#
# Requirement: aws_servicecatalog_portfolio_share resources must NOT have type='ACCOUNT'
# Valid types: ORGANIZATION, ORGANIZATIONAL_UNIT, ORGANIZATION_MEMBER_ACCOUNT
#
# Reference: https://docs.aws.amazon.com/securityhub/latest/userguide/servicecatalog-controls.html#servicecatalog-1

resource_policy "aws_servicecatalog_portfolio_share" "shared_within_organization" {

  enforcement_level = "advisory"
    locals {
        # Get the share type, default to "ACCOUNT" if not specified (to catch violations)
        share_type = core::try(attrs.type, "ACCOUNT")
        
        # Check if the share type is not ACCOUNT (compliant)
        is_compliant = local.share_type != "ACCOUNT"
    }
    
    enforce {
        condition = local.is_compliant
  error_message = "Attribute 'type' must not be 'ACCOUNT' for 'aws_servicecatalog_portfolio_share' resource. Use 'ORGANIZATION', 'ORGANIZATIONAL_UNIT', or 'ORGANIZATION_MEMBER_ACCOUNT' instead. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/servicecatalog-controls.html#servicecatalog-1 for more details."
    }
}