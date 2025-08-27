# ===================================================================
# AWS Platform Audit System - Hub Account Providers Configuration
# ===================================================================
# This file defines the provider configurations for the hub account
# including AWS provider settings and backend configuration.
# ===================================================================

terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.4"
    }
    null = {
      source  = "hashicorp/null"
      version = "~> 3.2"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  # Backend configuration for state management
  # Uncomment and configure for production use
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "aws-audit-platform/hub/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-lock-table"
  # }
}

# ===================================================================
# AWS Provider Configuration - Primary Region (Hub)
# ===================================================================

provider "aws" {
  region = var.region
  
  default_tags {
    tags = {
      Project             = var.project_name
      Environment         = var.environment
      ManagedBy          = "Terraform"
      Component          = "hub-account"
      SecurityLevel      = "Critical"
      ComplianceFramework = "Multi-Framework"
      DataClassification = "Confidential"
      Owner              = var.owner_team
      CostCenter         = var.cost_center
      BusinessUnit       = var.business_unit
      BackupRequired     = "true"
      MonitoringLevel    = "Enhanced"
      AutomatedRemediation = var.enable_automated_remediation ? "enabled" : "disabled"
    }
  }
}

# ===================================================================
# AWS Provider Aliases for Multi-Region Deployments
# ===================================================================

# US East 1 (N. Virginia) - Primary region for global services
provider "aws" {
  alias  = "us-east-1"
  region = "us-east-1"
  
  default_tags {
    tags = {
      Project             = var.project_name
      Environment         = var.environment
      ManagedBy          = "Terraform"
      Component          = "hub-account-us-east-1"
      Region             = "us-east-1"
      SecurityLevel      = "Critical"
      ComplianceFramework = "Multi-Framework"
      DataClassification = "Confidential"
      Owner              = var.owner_team
      CostCenter         = var.cost_center
      BusinessUnit       = var.business_unit
    }
  }
}

# US East 2 (Ohio)
provider "aws" {
  alias  = "us-east-2"
  region = "us-east-2"
  
  default_tags {
    tags = {
      Project             = var.project_name
      Environment         = var.environment
      ManagedBy          = "Terraform"
      Component          = "hub-account-us-east-2"
      Region             = "us-east-2"
      SecurityLevel      = "Critical"
      ComplianceFramework = "Multi-Framework"
      DataClassification = "Confidential"
      Owner              = var.owner_team
      CostCenter         = var.cost_center
      BusinessUnit       = var.business_unit
    }
  }
}

# US West 1 (N. California)
provider "aws" {
  alias  = "us-west-1"
  region = "us-west-1"
  
  default_tags {
    tags = {
      Project             = var.project_name
      Environment         = var.environment
      ManagedBy          = "Terraform"
      Component          = "hub-account-us-west-1"
      Region             = "us-west-1"
      SecurityLevel      = "Critical"
      ComplianceFramework = "Multi-Framework"
      DataClassification = "Confidential"
      Owner              = var.owner_team
      CostCenter         = var.cost_center
      BusinessUnit       = var.business_unit
    }
  }
}

# US West 2 (Oregon) - Backup region
provider "aws" {
  alias  = "us-west-2"
  region = "us-west-2"
  
  default_tags {
    tags = {
      Project             = var.project_name
      Environment         = var.environment
      ManagedBy          = "Terraform"
      Component          = "hub-account-us-west-2"
      Region             = "us-west-2"
      SecurityLevel      = "Critical"
      ComplianceFramework = "Multi-Framework"
      DataClassification = "Confidential"
      Owner              = var.owner_team
      CostCenter         = var.cost_center
      BusinessUnit       = var.business_unit
      BackupRegion       = "true"
    }
  }
}

# EU West 1 (Ireland)
provider "aws" {
  alias  = "eu-west-1"
  region = "eu-west-1"
  
  default_tags {
    tags = {
      Project             = var.project_name
      Environment         = var.environment
      ManagedBy          = "Terraform"
      Component          = "hub-account-eu-west-1"
      Region             = "eu-west-1"
      SecurityLevel      = "Critical"
      ComplianceFramework = "Multi-Framework"
      DataClassification = "Confidential"
      Owner              = var.owner_team
      CostCenter         = var.cost_center
      BusinessUnit       = var.business_unit
      DataResidency      = "EU"
    }
  }
}

# EU Central 1 (Frankfurt)
provider "aws" {
  alias  = "eu-central-1"
  region = "eu-central-1"
  
  default_tags {
    tags = {
      Project             = var.project_name
      Environment         = var.environment
      ManagedBy          = "Terraform"
      Component          = "hub-account-eu-central-1"
      Region             = "eu-central-1"
      SecurityLevel      = "Critical"
      ComplianceFramework = "Multi-Framework"
      DataClassification = "Confidential"
      Owner              = var.owner_team
      CostCenter         = var.cost_center
      BusinessUnit       = var.business_unit
      DataResidency      = "EU"
    }
  }
}

# Asia Pacific Southeast 1 (Singapore)
provider "aws" {
  alias  = "ap-southeast-1"
  region = "ap-southeast-1"
  
  default_tags {
    tags = {
      Project             = var.project_name
      Environment         = var.environment
      ManagedBy          = "Terraform"
      Component          = "hub-account-ap-southeast-1"
      Region             = "ap-southeast-1"
      SecurityLevel      = "Critical"
      ComplianceFramework = "Multi-Framework"
      DataClassification = "Confidential"
      Owner              = var.owner_team
      CostCenter         = var.cost_center
      BusinessUnit       = var.business_unit
      DataResidency      = "APAC"
    }
  }
}

# Asia Pacific Southeast 2 (Sydney)
provider "aws" {
  alias  = "ap-southeast-2"
  region = "ap-southeast-2"
  
  default_tags {
    tags = {
      Project             = var.project_name
      Environment         = var.environment
      ManagedBy          = "Terraform"
      Component          = "hub-account-ap-southeast-2"
      Region             = "ap-southeast-2"
      SecurityLevel      = "Critical"
      ComplianceFramework = "Multi-Framework"
      DataClassification = "Confidential"
      Owner              = var.owner_team
      CostCenter         = var.cost_center
      BusinessUnit       = var.business_unit
      DataResidency      = "APAC"
    }
  }
}
