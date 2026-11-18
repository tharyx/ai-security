# VULNERABLE: AI platform infrastructure for the "support-llm" team.
#
# This file is for READING ONLY. It is the source of plans/vulnerable.plan.json.
# Every block marked VULN is a mistake the policy checker (policy_check.py) must catch.
# Do not apply this to a real AWS account.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "eu-west-1"
}

# VULN (TF-AI-050): key rotation is off.
resource "aws_kms_key" "ai" {
  description             = "AI platform key"
  enable_key_rotation     = false
  deletion_window_in_days = 7
}

# ---------------------------------------------------------------- model + data buckets
resource "aws_s3_bucket" "model_artifacts" {
  bucket        = "acme-llm-model-artifacts"
  force_destroy = true
  tags          = { team = "support-llm" }
}
# VULN (TF-AI-001, TF-AI-004, TF-AI-005): no public access block, no versioning, no access logs.

# VULN (TF-AI-002): "so the inference cluster in the other account can download it".
resource "aws_s3_bucket_acl" "model_artifacts" {
  bucket = aws_s3_bucket.model_artifacts.id
  acl    = "public-read"
}

# VULN (TF-AI-003): encrypted, but with an AWS-owned key (AES256), not a customer-managed key.
resource "aws_s3_bucket_server_side_encryption_configuration" "model_artifacts" {
  bucket = aws_s3_bucket.model_artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# VULN (TF-AI-001, 003, 004, 005): training data with no hardening at all.
resource "aws_s3_bucket" "training_data" {
  bucket = "acme-llm-training-data"
  tags   = { team = "support-llm" }
}

# ---------------------------------------------------------------- notebooks
# VULN (TF-AI-010): internet access, root access, and no VPC subnet.
resource "aws_sagemaker_notebook_instance" "research" {
  name                   = "support-llm-research"
  instance_type          = "ml.t3.medium"
  role_arn               = aws_iam_role.sagemaker_exec.arn
  direct_internet_access = "Enabled"
  root_access            = "Enabled"
}

# ---------------------------------------------------------------- model serving
# VULN (TF-AI-011): the serving container can reach the internet and is not in our VPC.
resource "aws_sagemaker_model" "support_llm" {
  name                     = "support-llm-v3"
  execution_role_arn       = aws_iam_role.sagemaker_exec.arn
  enable_network_isolation = false
  primary_container {
    image          = "111122223333.dkr.ecr.eu-west-1.amazonaws.com/support-llm:latest"
    model_data_url = "s3://acme-llm-model-artifacts/support-llm/v3/model.tar.gz"
  }
}

# VULN (TF-AI-012): the endpoint's storage volume is not encrypted with our key.
resource "aws_sagemaker_endpoint_configuration" "support_llm" {
  name = "support-llm-v3"
  production_variants {
    variant_name           = "primary"
    model_name             = aws_sagemaker_model.support_llm.name
    instance_type          = "ml.g5.xlarge"
    initial_instance_count = 1
  }
}

# VULN (TF-AI-013): no interface VPC endpoint, so callers use the public regional API endpoint.
resource "aws_sagemaker_endpoint" "support_llm" {
  name                 = "support-llm"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.support_llm.name
}

# ---------------------------------------------------------------- self-managed Ray cluster
# VULN (TF-AI-030): Ray dashboard / Jobs API and Redis port open to the whole internet.
resource "aws_security_group" "ray_head" {
  name   = "ray-head"
  vpc_id = "vpc-0a1b2c3d4e5f60718"
  ingress {
    description = "Ray dashboard and Jobs API"
    from_port   = 8265
    to_port     = 8265
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    description = "Ray GCS"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------- vector database
# VULN (TF-AI-020, TF-AI-021): public endpoint, open access policy, no encryption, no HTTPS.
resource "aws_opensearch_domain" "vectors" {
  domain_name    = "support-llm-vectors"
  engine_version = "OpenSearch_2.13"
  encrypt_at_rest { enabled = false }
  node_to_node_encryption { enabled = false }
  domain_endpoint_options { enforce_https = false }
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }
      Action    = "es:*"
      Resource  = "arn:aws:es:eu-west-1:111122223333:domain/support-llm-vectors/*"
    }]
  })
}

# ---------------------------------------------------------------- identities
resource "aws_iam_role" "sagemaker_exec" {
  name = "support-llm-sagemaker"
  assume_role_policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Principal = { Service = "sagemaker.amazonaws.com" }, Action = "sts:AssumeRole" }]
  })
}

# VULN (TF-AI-040): "it was easier to debug with full access".
resource "aws_iam_role_policy" "sagemaker_exec" {
  name = "everything"
  role = aws_iam_role.sagemaker_exec.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = "*", Resource = "*" }]
  })
}

# VULN (TF-AI-041): a long-lived access key for the CI pipeline.
resource "aws_iam_user" "ci_deployer" {
  name = "ci-deployer"
}
resource "aws_iam_access_key" "ci_deployer" {
  user = aws_iam_user.ci_deployer.name
}

# VULN (TF-AI-042): half-finished OIDC migration. The trust policy checks the audience
# but not the subject, so ANY GitHub repository can assume this role.
resource "aws_iam_role" "ci_oidc" {
  name = "ci-oidc-deployer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = { StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" } }
    }]
  })
}

# VULN (TF-AI-060): no CloudTrail data events, so nobody can tell who downloaded the model.
