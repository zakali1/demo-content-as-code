terraform {
  required_providers {
    sumologic = {
      source = "SumoLogic/sumologic"
      version = ">= 3.0.5"
    }
  }

  # This backend looks for these environment variables by default:
  #   AWS_ACCESS_KEY_ID
  #   AWS_SECRET_ACCESS_KEY
  # For more details on the permissions needed (bucket policy), see: https://developer.hashicorp.com/terraform/language/backend/s3#permissions-required
  backend "s3" {
    bucket         = "zak-tf-state1"
    key            = "terraform-state"
    region         = "eu-west-2"
  }
}
