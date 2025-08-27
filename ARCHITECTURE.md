# AWS Audit Platform - Architecture Diagram

## System Architecture Overview

```mermaid
graph TB
    %% External Users
    subgraph "Users & Interfaces"
        EU[Executive Users]
        OU[Operations Users]
        SU[Security Users]
        AU[Audit Users]
    end

    %% Hub Account (Security Command Center)
    subgraph "Hub Account - Security Command Center"
        subgraph "Data Ingestion Layer"
            EB[EventBridge Custom Bus]
            CR[CloudWatch Events Rules]
        end
        
        subgraph "Processing Layer"
            LF1[Security Findings Processor]
            LF2[Dashboard Generator]
            LF3[Cost Analyzer]
            LF4[Compliance Reporter]
        end
        
        subgraph "Security Services Hub"
            SH[Security Hub Master]
            GD[GuardDuty Master]
            CF[Config Aggregator]
            AA[Access Analyzer]
            CT[CloudTrail Organization]
        end
        
        subgraph "Data Layer"
            S3DL[S3 Data Lake]
            S3B[S3 Backup Bucket]
            KMS[KMS Keys]
        end
        
        subgraph "Monitoring & Alerting"
            CWD[CloudWatch Dashboards]
            CWA[CloudWatch Alarms]
            SNS[SNS Topics]
            SES[SES Email Service]
        end
        
        subgraph "Analytics & Reporting"
            QS[QuickSight Dashboards]
            AT[Athena Queries]
            GL[Glue Data Catalog]
        end
    end

    %% Spoke Accounts
    subgraph "Spoke Account 1 - Production"
        subgraph "Security Services"
            SH1[Security Hub]
            GD1[GuardDuty]
            CF1[Config]
            AA1[Access Analyzer]
            IN1[Inspector v2]
            MC1[Macie]
            CT1[CloudTrail]
        end
        
        subgraph "Resources Being Monitored"
            EC2_1[EC2 Instances]
            S3_1[S3 Buckets]
            RDS_1[RDS Databases]
            IAM_1[IAM Resources]
            VPC_1[VPC Resources]
            LAM_1[Lambda Functions]
        end
    end

    subgraph "Spoke Account 2 - Development"
        subgraph "Security Services"
            SH2[Security Hub]
            GD2[GuardDuty]
            CF2[Config]
            AA2[Access Analyzer]
            IN2[Inspector v2]
            CT2[CloudTrail]
        end
        
        subgraph "Resources Being Monitored"
            EC2_2[EC2 Instances]
            S3_2[S3 Buckets]
            IAM_2[IAM Resources]
            VPC_2[VPC Resources]
        end
    end

    subgraph "Spoke Account N - ..."
        SHN[Security Hub]
        GDN[GuardDuty]
        CFN[Config]
        AAN[Access Analyzer]
        INN[Inspector v2]
        MCN[Macie]
        CTN[CloudTrail]
    end

    %% External Integrations
    subgraph "External Integrations"
        SLACK[Slack Notifications]
        TEAMS[Teams Notifications]
        SIEM[External SIEM]
        JIRA[Jira Ticketing]
    end

    %% CI/CD Pipeline
    subgraph "CI/CD Pipeline"
        GH[GitHub Repository]
        GA[GitHub Actions]
        TF[Terraform Cloud]
    end

    %% Data Flow Connections
    SH1 -->|Security Findings| EB
    GD1 -->|Threat Intelligence| EB
    CF1 -->|Compliance Data| EB
    AA1 -->|Access Analysis| EB
    IN1 -->|Vulnerability Data| EB
    MC1 -->|Data Classification| EB
    CT1 -->|Audit Logs| EB

    SH2 -->|Security Findings| EB
    GD2 -->|Threat Intelligence| EB
    CF2 -->|Compliance Data| EB
    AA2 -->|Access Analysis| EB
    IN2 -->|Vulnerability Data| EB
    CT2 -->|Audit Logs| EB

    SHN -->|Security Findings| EB
    GDN -->|Threat Intelligence| EB
    CFN -->|Compliance Data| EB
    AAN -->|Access Analysis| EB
    INN -->|Vulnerability Data| EB
    MCN -->|Data Classification| EB
    CTN -->|Audit Logs| EB

    %% Event Processing
    EB --> CR
    CR --> LF1
    CR --> LF2
    CR --> LF3
    CR --> LF4

    %% Data Storage
    LF1 --> S3DL
    LF2 --> S3DL
    LF3 --> S3DL
    LF4 --> S3DL

    %% Hub Services
    LF1 --> SH
    LF1 --> GD
    LF1 --> CF
    LF1 --> AA

    %% Monitoring
    LF1 --> CWD
    LF2 --> CWD
    LF3 --> CWD
    LF4 --> CWD

    %% Alerting
    LF1 --> SNS
    LF3 --> SNS
    LF4 --> SNS
    SNS --> SES
    SNS --> SLACK
    SNS --> TEAMS

    %% Analytics
    S3DL --> GL
    GL --> AT
    AT --> QS

    %% User Access
    EU --> QS
    EU --> CWD
    OU --> CWD
    SU --> CWD
    AU --> QS

    %% External Integrations
    SNS --> SIEM
    LF1 --> JIRA

    %% CI/CD
    GH --> GA
    GA --> TF
    TF --> Hub Account
    TF --> "Spoke Account 1"
    TF --> "Spoke Account 2"

    %% Resource Monitoring
    EC2_1 --> SH1
    S3_1 --> MC1
    RDS_1 --> GD1
    IAM_1 --> AA1
    VPC_1 --> CF1
    LAM_1 --> IN1

    EC2_2 --> SH2
    S3_2 --> GD2
    IAM_2 --> AA2
    VPC_2 --> CF2

    %% Styling
    classDef hubAccount fill:#ff9999,stroke:#333,stroke-width:2px
    classDef spokeAccount fill:#99ccff,stroke:#333,stroke-width:2px
    classDef processing fill:#99ff99,stroke:#333,stroke-width:2px
    classDef data fill:#ffcc99,stroke:#333,stroke-width:2px
    classDef external fill:#cc99ff,stroke:#333,stroke-width:2px

    class "Hub Account - Security Command Center" hubAccount
    class "Spoke Account 1 - Production","Spoke Account 2 - Development","Spoke Account N - ..." spokeAccount
    class LF1,LF2,LF3,LF4 processing
    class S3DL,S3B,KMS data
    class SLACK,TEAMS,SIEM,JIRA external
```

## Network Architecture

```mermaid
graph TB
    subgraph "AWS Organizations"
        subgraph "Security OU"
            subgraph "Hub Account VPC"
                subgraph "Private Subnets"
                    LF[Lambda Functions]
                    VE[VPC Endpoints]
                end
                subgraph "Public Subnets"
                    NG[NAT Gateway]
                    ALB[Application Load Balancer]
                end
            end
        end
        
        subgraph "Production OU"
            subgraph "Prod Account 1 VPC"
                subgraph "Private Subnets - Prod"
                    APP1[Application Resources]
                    DB1[Database Resources]
                end
                subgraph "Public Subnets - Prod"
                    WEB1[Web Tier]
                end
            end
        end
        
        subgraph "Development OU"
            subgraph "Dev Account VPC"
                subgraph "Private Subnets - Dev"
                    APP2[Application Resources]
                    DB2[Database Resources]
                end
            end
        end
    end

    subgraph "AWS Services"
        S3[S3 Service]
        SH[Security Hub]
        GD[GuardDuty]
        CF[Config]
    end

    %% Network Connections
    LF <--> VE
    VE <--> S3
    VE <--> SH
    VE <--> GD
    VE <--> CF
    
    APP1 --> VE
    DB1 --> VE
    WEB1 --> NG
    
    APP2 --> VE
    DB2 --> VE

    %% Styling
    classDef vpc fill:#e1f5fe,stroke:#01579b,stroke-width:2px
    classDef subnet fill:#f3e5f5,stroke:#4a148c,stroke-width:1px
    classDef service fill:#fff3e0,stroke:#e65100,stroke-width:2px

    class "Hub Account VPC","Prod Account 1 VPC","Dev Account VPC" vpc
    class "Private Subnets","Public Subnets","Private Subnets - Prod","Public Subnets - Prod","Private Subnets - Dev" subnet
    class S3,SH,GD,CF service
```

## Data Flow Architecture

```mermaid
sequenceDiagram
    participant SA as Spoke Account
    participant EB as EventBridge
    participant LF as Lambda Processor
    participant SH as Security Hub
    participant S3 as S3 Data Lake
    participant CW as CloudWatch
    participant SNS as SNS
    participant USER as End User

    Note over SA,USER: Real-time Security Finding Processing

    SA->>EB: Security Finding Event
    EB->>LF: Trigger Lambda Function
    
    LF->>LF: Process & Enrich Finding
    LF->>SH: Update Security Hub
    LF->>S3: Store Raw Finding
    LF->>CW: Publish Metrics
    
    alt Critical Finding
        LF->>SNS: Send Alert
        SNS->>USER: Email/Slack Notification
    end
    
    Note over CW,USER: Dashboard Updates
    CW->>USER: Real-time Dashboard Update
    
    Note over S3,USER: Analytics & Reporting
    S3->>USER: Historical Analysis
```

## Security Architecture

```mermaid
graph TB
    subgraph "Identity & Access Management"
        subgraph "Hub Account IAM"
            HR1[SecurityHubServiceRole]
            HR2[GuardDutyServiceRole]
            HR3[ConfigServiceRole]
            HR4[LambdaExecutionRole]
            HR5[CrossAccountAccessRole]
        end
        
        subgraph "Spoke Account IAM"
            SR1[SecurityHubSpokeRole]
            SR2[GuardDutySpokeRole]
            SR3[ConfigSpokeRole]
            SR4[CrossAccountTrustRole]
        end
        
        subgraph "Cross-Account Trust"
            CT1[Hub → Spoke Trust]
            CT2[Spoke → Hub Trust]
        end
    end

    subgraph "Data Protection"
        subgraph "Encryption at Rest"
            KMS1[KMS Keys for S3]
            KMS2[KMS Keys for CloudWatch]
            KMS3[KMS Keys for SNS]
        end
        
        subgraph "Encryption in Transit"
            TLS1[TLS 1.2+ for API Calls]
            TLS2[HTTPS for Web Traffic]
            TLS3[SSL for Database]
        end
        
        subgraph "Access Control"
            BP1[S3 Bucket Policies]
            BP2[Resource-based Policies]
            BP3[VPC Endpoints]
        end
    end

    subgraph "Network Security"
        subgraph "VPC Security"
            SG1[Security Groups]
            NACL1[Network ACLs]
            FL1[VPC Flow Logs]
        end
        
        subgraph "DNS Security"
            R531[Route 53 Resolver]
            DNS1[DNS Query Logging]
        end
    end

    subgraph "Monitoring & Auditing"
        subgraph "Audit Logging"
            CT_LOG[CloudTrail Logs]
            CONFIG_LOG[Config History]
            VPC_LOG[VPC Flow Logs]
        end
        
        subgraph "Real-time Monitoring"
            GD_MON[GuardDuty Monitoring]
            SH_MON[Security Hub Monitoring]
            CW_MON[CloudWatch Monitoring]
        end
    end

    %% Security Flow
    HR5 --> CT1
    CT1 --> SR4
    SR4 --> CT2
    CT2 --> HR5

    %% Data Protection Flow
    S3 --> KMS1
    CloudWatch --> KMS2
    SNS --> KMS3

    %% Network Security Flow
    VPC --> SG1
    VPC --> NACL1
    VPC --> FL1

    %% Monitoring Flow
    All_Services --> CT_LOG
    All_Services --> GD_MON
    All_Services --> CW_MON

    %% Styling
    classDef iam fill:#ffe0b2,stroke:#ef6c00,stroke-width:2px
    classDef encryption fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef network fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef monitoring fill:#fce4ec,stroke:#c2185b,stroke-width:2px

    class HR1,HR2,HR3,HR4,HR5,SR1,SR2,SR3,SR4,CT1,CT2 iam
    class KMS1,KMS2,KMS3,TLS1,TLS2,TLS3,BP1,BP2,BP3 encryption
    class SG1,NACL1,FL1,R531,DNS1 network
    class CT_LOG,CONFIG_LOG,VPC_LOG,GD_MON,SH_MON,CW_MON monitoring
```

## Deployment Architecture

```mermaid
graph TB
    subgraph "Source Control"
        GH[GitHub Repository]
        BR1[Main Branch]
        BR2[Development Branch]
        BR3[Feature Branches]
    end

    subgraph "CI/CD Pipeline"
        subgraph "GitHub Actions"
            JOB1[Lint & Validate]
            JOB2[Security Scan]
            JOB3[Unit Tests]
            JOB4[Integration Tests]
            JOB5[Deploy to Dev]
            JOB6[Deploy to Staging]
            JOB7[Deploy to Production]
        end
    end

    subgraph "Terraform State Management"
        TFC[Terraform Cloud]
        S3_STATE[S3 State Backend]
        LOCK[DynamoDB Lock Table]
    end

    subgraph "Environment Progression"
        subgraph "Development Environment"
            DEV_HUB[Dev Hub Account]
            DEV_SPOKE[Dev Spoke Accounts]
        end
        
        subgraph "Staging Environment"
            STAGE_HUB[Staging Hub Account]
            STAGE_SPOKE[Staging Spoke Accounts]
        end
        
        subgraph "Production Environment"
            PROD_HUB[Production Hub Account]
            PROD_SPOKE[Production Spoke Accounts]
        end
    end

    subgraph "Monitoring & Validation"
        HEALTH[Health Checks]
        SMOKE[Smoke Tests]
        ROLLBACK[Rollback Procedures]
    end

    %% Source Control Flow
    BR3 --> BR2
    BR2 --> BR1
    BR1 --> JOB1

    %% CI/CD Pipeline Flow
    JOB1 --> JOB2
    JOB2 --> JOB3
    JOB3 --> JOB4
    JOB4 --> JOB5
    JOB5 --> JOB6
    JOB6 --> JOB7

    %% Terraform Flow
    JOB5 --> TFC
    JOB6 --> TFC
    JOB7 --> TFC
    TFC --> S3_STATE
    TFC --> LOCK

    %% Environment Deployment
    JOB5 --> DEV_HUB
    JOB5 --> DEV_SPOKE
    JOB6 --> STAGE_HUB
    JOB6 --> STAGE_SPOKE
    JOB7 --> PROD_HUB
    JOB7 --> PROD_SPOKE

    %% Validation Flow
    DEV_HUB --> HEALTH
    STAGE_HUB --> SMOKE
    PROD_HUB --> ROLLBACK

    %% Styling
    classDef source fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef cicd fill:#e3f2fd,stroke:#1565c0,stroke-width:2px
    classDef terraform fill:#fff3e0,stroke:#e65100,stroke-width:2px
    classDef environment fill:#fce4ec,stroke:#c2185b,stroke-width:2px

    class GH,BR1,BR2,BR3 source
    class JOB1,JOB2,JOB3,JOB4,JOB5,JOB6,JOB7 cicd
    class TFC,S3_STATE,LOCK terraform
    class DEV_HUB,DEV_SPOKE,STAGE_HUB,STAGE_SPOKE,PROD_HUB,PROD_SPOKE environment
```

## Cost Architecture

```mermaid
graph TB
    subgraph "Cost Components"
        subgraph "AWS Security Services"
            C_SH[Security Hub: $3,000/month]
            C_GD[GuardDuty: $15,000/month]
            C_CF[Config: $8,000/month]
            C_IN[Inspector: $5,000/month]
            C_MC[Macie: $2,000/month]
            C_CT[CloudTrail: $2,000/month]
        end
        
        subgraph "Compute & Storage"
            C_LF[Lambda: $1,000/month]
            C_S3[S3 Storage: $1,500/month]
            C_CW[CloudWatch: $500/month]
        end
        
        subgraph "Data Transfer"
            C_DT[Data Transfer: $500/month]
            C_VE[VPC Endpoints: $200/month]
        end
    end

    subgraph "Cost Optimization"
        subgraph "Automated Optimization"
            OPT1[S3 Intelligent Tiering]
            OPT2[Lambda Reserved Concurrency]
            OPT3[CloudWatch Log Retention]
            OPT4[Config Rule Optimization]
        end
        
        subgraph "Cost Monitoring"
            MON1[Daily Cost Analysis]
            MON2[Anomaly Detection]
            MON3[Budget Alerts]
            MON4[Forecast Analysis]
        end
    end

    subgraph "Total Cost Summary"
        TOTAL[Total: $36,000/month for 1000 accounts]
        PER_ACCOUNT[Cost per Account: $36/month]
        OPTIMIZATION[Potential Savings: 20-30%]
    end

    %% Cost Flow
    C_SH --> TOTAL
    C_GD --> TOTAL
    C_CF --> TOTAL
    C_IN --> TOTAL
    C_MC --> TOTAL
    C_CT --> TOTAL
    C_LF --> TOTAL
    C_S3 --> TOTAL
    C_CW --> TOTAL
    C_DT --> TOTAL
    C_VE --> TOTAL

    %% Optimization Flow
    OPT1 --> C_S3
    OPT2 --> C_LF
    OPT3 --> C_CW
    OPT4 --> C_CF

    %% Monitoring Flow
    MON1 --> OPTIMIZATION
    MON2 --> OPTIMIZATION
    MON3 --> OPTIMIZATION
    MON4 --> OPTIMIZATION

    %% Styling
    classDef cost fill:#ffebee,stroke:#c62828,stroke-width:2px
    classDef optimization fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef summary fill:#e3f2fd,stroke:#1565c0,stroke-width:2px

    class C_SH,C_GD,C_CF,C_IN,C_MC,C_CT,C_LF,C_S3,C_CW,C_DT,C_VE cost
    class OPT1,OPT2,OPT3,OPT4,MON1,MON2,MON3,MON4 optimization
    class TOTAL,PER_ACCOUNT,OPTIMIZATION summary
```

## Technology Stack

```mermaid
mindmap
  root((AWS Audit Platform))
    Infrastructure
      Terraform
        Hub Account IaC
        Spoke Account IaC
        Multi-Environment
      AWS Services
        Security Hub
        GuardDuty
        Config
        Access Analyzer
        Inspector v2
        Macie
        CloudTrail
      Compute
        Lambda Functions
        EventBridge
        Step Functions
    Data & Analytics
      Storage
        S3 Data Lake
        S3 Intelligent Tiering
        Glacier Deep Archive
      Processing
        Glue Data Catalog
        Athena Queries
        Lambda Analytics
      Visualization
        CloudWatch Dashboards
        QuickSight
        Custom Metrics
    Development
      Languages
        Python 3.11
        HCL (Terraform)
        YAML
        JSON
      Tools
        VS Code
        GitHub
        GitHub Actions
        Terraform Cloud
      Testing
        pytest
        moto
        tfsec
        checkov
    Monitoring
      Observability
        CloudWatch Logs
        CloudWatch Metrics
        X-Ray Tracing
      Alerting
        SNS Topics
        SES Email
        Slack Integration
        Teams Integration
      Security
        AWS Organizations
        IAM Roles & Policies
        KMS Encryption
        VPC Security
```

---

## Architecture Decision Records (ADRs)

### ADR-001: Hub-and-Spoke Architecture
**Decision**: Implement centralized hub account with distributed spoke accounts  
**Rationale**: Provides centralized visibility while maintaining account isolation  
**Consequences**: Simplified management, better compliance, potential single point of failure  

### ADR-002: Event-Driven Processing
**Decision**: Use EventBridge and Lambda for real-time processing  
**Rationale**: Scalable, cost-effective, and provides near real-time processing  
**Consequences**: Better responsiveness, complexity in error handling  

### ADR-003: S3 Data Lake Architecture
**Decision**: Store all security findings in S3 with structured partitioning  
**Rationale**: Cost-effective storage, enables analytics, supports compliance retention  
**Consequences**: Complex data management, powerful analytics capabilities  

### ADR-004: Multi-Environment Strategy
**Decision**: Separate dev, staging, and production environments  
**Rationale**: Safe deployment practices, testing isolation, production stability  
**Consequences**: Increased infrastructure complexity, better quality assurance  

---

**Architecture Documentation Version**: 2.0  
**Last Updated**: August 27, 2025  
**Next Review**: November 27, 2025  
**Architecture Owner**: Security Engineering Team
