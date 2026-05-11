terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# AWS IAM Role for Lambda with broad S3 access
resource "aws_iam_role" "lambda_execution" {
  name = "lambda-execution-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "lambda.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy" "lambda_s3_access" {
  name = "lambda-s3-access"
  role = aws_iam_role.lambda_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:*"]
        Resource = "*"
      }
    ]
  })
}

# Azure Role Assignment — Contributor to a Service Principal
resource "azurerm_role_assignment" "deploy_sp_contributor" {
  scope                = "/subscriptions/12345678-abcd-1234-abcd-123456789012/resourceGroups/production-rg"
  role_definition_name = "Contributor"
  principal_id         = "a1b2c3d4-0000-0000-0000-000000000001"
}

# GCP IAM Binding — Editor role (overly broad)
resource "google_project_iam_binding" "data_pipeline_editor" {
  project = "my-gcp-project"
  role    = "roles/editor"

  members = [
    "serviceAccount:data-pipeline@my-gcp-project.iam.gserviceaccount.com",
  ]
}

# GCP Service Account
resource "google_service_account" "data_pipeline" {
  account_id   = "data-pipeline"
  display_name = "Data Pipeline Service Account"
  project      = "my-gcp-project"
}
