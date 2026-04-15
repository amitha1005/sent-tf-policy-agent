# Validate aws_servicecatalog_portfolio
resource "aws_servicecatalog_portfolio" "validation_test" {
  name          = "Test Portfolio"
  description   = "Test portfolio for validation"
  provider_name = "Test Provider"
}

# Validate aws_servicecatalog_portfolio_share
resource "aws_servicecatalog_portfolio_share" "validation_test" {
  portfolio_id = aws_servicecatalog_portfolio.validation_test.id
  principal_id = "123456789012"
  type         = "ORGANIZATION"
}