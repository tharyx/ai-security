# SECURE: the same AI platform, hardened.
#
# This file is for READING ONLY. It is the source of plans/secure.plan.json.
# Compare it with ../vulnerable/main.tf block by block. Each "FIX" names the rule it satisfies.
# Existing network pieces (VPC, subnets) come from the platform team as variables.

terraform {
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.0" }
  }
}

provider "aws" {
  region = "eu-west-1"
}

variable "vpc_id" { default = "vpc-0a1b2c3d4e5f60718" }
variable "vpc_cidr" { default = "10.20.0.0/16" }
variable "private_subnet_ids" { default = ["subnet-0aaa1111bbbb22223", "subnet-0ccc3333dddd44445"] }
variable "account_id" { default = "111122223333" }

# FIX (TF-AI-050): customer-managed key (CMEK) with automatic rotation.
resource "aws_kms_key" "ai" {
  description             = "AI platform key: model artifacts, training data, endpoints"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

# ---------------------------------------------------------------- buckets
locals {
  buckets = {
    model_artifacts = "acme-llm-model-artifacts"
    training_data   = "acme-llm-training-data"
    access_logs     = "acme-llm-access-logs"
  }
}

resource "aws_s3_bucket" "model_artifacts" {
  bucket = local.buckets.model_artifacts
  tags   = { team = "support-llm", data_classification = "confidential" }
}
resource "aws_s3_bucket" "training_data" {
  bucket = local.buckets.training_data
  tags   = { team = "support-llm", data_classification = "restricted" }
}
resource "aws_s3_bucket" "access_logs" {
  bucket = local.buckets.access_logs
  tags   = { team = "support-llm", purpose = "access-logs" }
}

# FIX (TF-AI-001): block every kind of public access, on every bucket.
resource "aws_s3_bucket_public_access_block" "model_artifacts" {
  bucket                  = aws_s3_bucket.model_artifacts.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_public_access_block" "training_data" {
  bucket                  = aws_s3_bucket.training_data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
resource "aws_s3_bucket_public_access_block" "access_logs" {
  bucket                  = aws_s3_bucket.access_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# FIX (TF-AI-003): SSE-KMS with OUR key. Only roles allowed by the key policy can decrypt.
resource "aws_s3_bucket_server_side_encryption_configuration" "model_artifacts" {
  bucket = aws_s3_bucket.model_artifacts.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.ai.arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "training_data" {
  bucket = aws_s3_bucket.training_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.ai.arn
    }
    bucket_key_enabled = true
  }
}
resource "aws_s3_bucket_server_side_encryption_configuration" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.ai.arn
    }
    bucket_key_enabled = true
  }
}

# FIX (TF-AI-004): versioning lets you recover a tampered or deleted model file.
resource "aws_s3_bucket_versioning" "model_artifacts" {
  bucket = aws_s3_bucket.model_artifacts.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_versioning" "training_data" {
  bucket = aws_s3_bucket.training_data.id
  versioning_configuration { status = "Enabled" }
}
resource "aws_s3_bucket_versioning" "access_logs" {
  bucket = aws_s3_bucket.access_logs.id
  versioning_configuration { status = "Enabled" }
}

# FIX (TF-AI-005): server access logs go to a separate bucket.
resource "aws_s3_bucket_logging" "model_artifacts" {
  bucket        = aws_s3_bucket.model_artifacts.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "model-artifacts/"
}
resource "aws_s3_bucket_logging" "training_data" {
  bucket        = aws_s3_bucket.training_data.id
  target_bucket = aws_s3_bucket.access_logs.id
  target_prefix = "training-data/"
}

# ---------------------------------------------------------------- notebooks
# FIX (TF-AI-010): no direct internet, no root, inside a private subnet, encrypted volume.
resource "aws_sagemaker_notebook_instance" "research" {
  name                   = "support-llm-research"
  instance_type          = "ml.t3.medium"
  role_arn               = aws_iam_role.sagemaker_exec.arn
  direct_internet_access = "Disabled"
  root_access            = "Disabled"
  subnet_id              = var.private_subnet_ids[0]
  security_groups        = [aws_security_group.model_endpoint.id]
  kms_key_id             = aws_kms_key.ai.arn
}

# ---------------------------------------------------------------- model serving
# FIX (TF-AI-011): network isolation (the container gets no outbound network) and VPC config.
resource "aws_sagemaker_model" "support_llm" {
  name                     = "support-llm-v3"
  execution_role_arn       = aws_iam_role.sagemaker_exec.arn
  enable_network_isolation = true
  primary_container {
    # Pinned by digest, not by a mutable tag. (The digest is a placeholder.)
    image          = "111122223333.dkr.ecr.eu-west-1.amazonaws.com/support-llm@sha256:1111111111111111111111111111111111111111111111111111111111111111"
    model_data_url = "s3://acme-llm-model-artifacts/support-llm/v3/model.tar.gz"
  }
  vpc_config {
    subnets            = var.private_subnet_ids
    security_group_ids = [aws_security_group.model_endpoint.id]
  }
}

# FIX (TF-AI-012): the endpoint's ML storage volume uses our key.
resource "aws_sagemaker_endpoint_configuration" "support_llm" {
  name        = "support-llm-v3"
  kms_key_arn = aws_kms_key.ai.arn
  production_variants {
    variant_name           = "primary"
    model_name             = aws_sagemaker_model.support_llm.name
    instance_type          = "ml.g5.xlarge"
    initial_instance_count = 1
  }
}

resource "aws_sagemaker_endpoint" "support_llm" {
  name                 = "support-llm"
  endpoint_config_name = aws_sagemaker_endpoint_configuration.support_llm.name
}

# FIX (TF-AI-013): callers inside the VPC reach the model API through a private endpoint.
resource "aws_vpc_endpoint" "sagemaker_runtime" {
  vpc_id              = var.vpc_id
  service_name        = "com.amazonaws.eu-west-1.sagemaker.runtime"
  vpc_endpoint_type   = "Interface"
  private_dns_enabled = true
  subnet_ids          = var.private_subnet_ids
  security_group_ids  = [aws_security_group.model_endpoint.id]
}

# FIX (TF-AI-030): only HTTPS, only from inside the VPC. (The Ray cluster was moved to
# a managed service with authentication and is no longer reachable from outside.)
resource "aws_security_group" "model_endpoint" {
  name   = "model-endpoint"
  vpc_id = var.vpc_id
  ingress {
    description = "HTTPS from inside the VPC only"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }
}

# ---------------------------------------------------------------- vector database
# FIX (TF-AI-020, TF-AI-021): VPC-only endpoint, a named principal, encryption, HTTPS + TLS 1.2.
resource "aws_opensearch_domain" "vectors" {
  domain_name    = "support-llm-vectors"
  engine_version = "OpenSearch_2.13"
  vpc_options {
    subnet_ids         = var.private_subnet_ids
    security_group_ids = [aws_security_group.model_endpoint.id]
  }
  encrypt_at_rest {
    enabled    = true
    kms_key_id = aws_kms_key.ai.arn
  }
  node_to_node_encryption { enabled = true }
  domain_endpoint_options {
    enforce_https       = true
    tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
  }
  access_policies = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "arn:aws:iam::111122223333:role/support-llm-rag-retriever" }
      Action    = ["es:ESHttpGet", "es:ESHttpPost"]
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

# FIX (TF-AI-040): read the one model prefix it serves. Nothing else.
# (kms:Decrypt is granted in the KMS key policy, scoped to this role.)
resource "aws_iam_role_policy" "sagemaker_exec" {
  name = "read-model-artifacts"
  role = aws_iam_role.sagemaker_exec.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:GetObject"], Resource = "arn:aws:s3:::acme-llm-model-artifacts/support-llm/*" },
      { Effect = "Allow", Action = ["s3:ListBucket"], Resource = "arn:aws:s3:::acme-llm-model-artifacts" }
    ]
  })
}

# FIX (TF-AI-041, TF-AI-042): no access keys. CI gets short-lived credentials through OIDC,
# and only for ONE repository, ONE environment.
resource "aws_iam_openid_connect_provider" "github" {
  url            = "https://token.actions.githubusercontent.com"
  client_id_list = ["sts.amazonaws.com"]
}

resource "aws_iam_role" "ci_oidc" {
  name = "ci-oidc-deployer"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com" }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = {
          "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
          "token.actions.githubusercontent.com:sub" = "repo:acme/support-llm:environment:production"
        }
      }
    }]
  })
}

# NOTE (TF-AI-060): CloudTrail data events for these buckets come from the organization
# trail managed by the security team, so this stack does not create its own trail.
# The policy check will flag it; ../waivers.json records the approved, time-limited exception.
