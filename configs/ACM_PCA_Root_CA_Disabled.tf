resource "aws_acmpca_certificate_authority" "validation_test" {
  type    = "ROOT"
  enabled = true

  certificate_authority_configuration {
    key_algorithm     = "RSA_4096"
    signing_algorithm = "SHA512WITHRSA"

    subject {
      common_name = "example.com"
    }
  }
}