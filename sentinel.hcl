module "report" {
  source = "./modules/report/report.sentinel"
}

module "tfresources" {
  source = "./modules/tfresources/tfresources.sentinel"
}

module "tfplan-functions" {
  source = "./modules/tfplan-functions/tfplan-functions.sentinel"
}

module "tfconfig-functions" {
  source = "./modules/tfconfig-functions/tfconfig-functions.sentinel"
}

policy "acm__acm-pca-root-ca-disabled" {
  source            = "./policies-sentinel/acm__acm-pca-root-ca-disabled.sentinel"
  enforcement_level = "advisory"
}

policy "api-gateway__api-gateway-access-logging-should-be-configured" {
  source            = "./policies-sentinel/api-gateway__api-gateway-access-logging-should-be-configured.sentinel"
  enforcement_level = "advisory"
}

policy "appsync__appsync-cache-should-be-encrypted-at-transit" {
  source            = "./policies-sentinel/appsync__appsync-cache-should-be-encrypted-at-transit.sentinel"
  enforcement_level = "advisory"
}

policy "athena__athena-workgroup-should-have-logging-enabled" {
  source            = "./policies-sentinel/athena__athena-workgroup-should-have-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "autoscaling-group__autoscaling-group-should-cover-multiple-azs" {
  source            = "./policies-sentinel/autoscaling-group__autoscaling-group-should-cover-multiple-azs.sentinel"
  enforcement_level = "advisory"
}

policy "backup__backup-recovery-point-encrypted" {
  source            = "./policies-sentinel/backup__backup-recovery-point-encrypted.sentinel"
  enforcement_level = "advisory"
}

policy "cloudfront__cloudfront-associated-with-waf" {
  source            = "./policies-sentinel/cloudfront__cloudfront-associated-with-waf.sentinel"
  enforcement_level = "advisory"
}

policy "cloudtrail__cloudtrail-cloudwatch-logs-group-arn-present" {
  source            = "./policies-sentinel/cloudtrail__cloudtrail-cloudwatch-logs-group-arn-present.sentinel"
  enforcement_level = "advisory"
}

policy "codebuild__codebuild-bitbucket-url-should-not-contain-sensitive-credentials" {
  source            = "./policies-sentinel/codebuild__codebuild-bitbucket-url-should-not-contain-sensitive-credentials.sentinel"
  enforcement_level = "advisory"
}

policy "connect__connect-instance-flow-logging-should-be-enabled" {
  source            = "./policies-sentinel/connect__connect-instance-flow-logging-should-be-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "datasync__datasync-task-should-have-logging-enabled" {
  source            = "./policies-sentinel/datasync__datasync-task-should-have-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "dms__dms-auto-minor-version-upgrade-check" {
  source            = "./policies-sentinel/dms__dms-auto-minor-version-upgrade-check.sentinel"
  enforcement_level = "advisory"
}

policy "docdb__docdb-cluster-audit-logging-enabled" {
  source            = "./policies-sentinel/docdb__docdb-cluster-audit-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "dynamo-db__dynamo-db-accelerator-clusters-encryption-at-rest-enabled" {
  source            = "./policies-sentinel/dynamo-db__dynamo-db-accelerator-clusters-encryption-at-rest-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "ec2__ec2-attached-ebs-volumes-encrypted-at-rest" {
  source            = "./policies-sentinel/ec2__ec2-attached-ebs-volumes-encrypted-at-rest.sentinel"
  enforcement_level = "advisory"
}

policy "ecr__ecr-image-scanning-enabled" {
  source            = "./policies-sentinel/ecr__ecr-image-scanning-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "ecs__ecs-cluster-enable-container-insights" {
  source            = "./policies-sentinel/ecs__ecs-cluster-enable-container-insights.sentinel"
  enforcement_level = "advisory"
}

policy "efs__efs-access-point-should-enforce-root-directory" {
  source            = "./policies-sentinel/efs__efs-access-point-should-enforce-root-directory.sentinel"
  enforcement_level = "advisory"
}

policy "eks__eks-cluster-audit-logging-enabled" {
  source            = "./policies-sentinel/eks__eks-cluster-audit-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "elasticache__elasticache-redis-cluster-auto-backup-enabled" {
  source            = "./policies-sentinel/elasticache__elasticache-redis-cluster-auto-backup-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "elasticbeanstalk__elasticbeanstalk-cloudwatch-log-streaming-enabled" {
  source            = "./policies-sentinel/elasticbeanstalk__elasticbeanstalk-cloudwatch-log-streaming-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "elasticsearch__elasticsearch-audit-logging-enabled" {
  source            = "./policies-sentinel/elasticsearch__elasticsearch-audit-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "elb__elb-configure-https-tls-termination-classic-load-balancer" {
  source            = "./policies-sentinel/elb__elb-configure-https-tls-termination-classic-load-balancer.sentinel"
  enforcement_level = "advisory"
}

policy "emr__emr-block-public-access-enabled" {
  source            = "./policies-sentinel/emr__emr-block-public-access-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "eventbridge__eventbridge-custom-event-bus-should-have-attached-policy" {
  source            = "./policies-sentinel/eventbridge__eventbridge-custom-event-bus-should-have-attached-policy.sentinel"
  enforcement_level = "advisory"
}

policy "fsx__fsx-lustre-copy-tags-to-backups" {
  source            = "./policies-sentinel/fsx__fsx-lustre-copy-tags-to-backups.sentinel"
  enforcement_level = "advisory"
}

policy "glue__glue-spark-job-supported-version" {
  source            = "./policies-sentinel/glue__glue-spark-job-supported-version.sentinel"
  enforcement_level = "advisory"
}

policy "guardduty__guardduty-ecs-protection-runtime-enabled" {
  source            = "./policies-sentinel/guardduty__guardduty-ecs-protection-runtime-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "iam__iam-no-admin-privileges-allowed-by-policies" {
  source            = "./policies-sentinel/iam__iam-no-admin-privileges-allowed-by-policies.sentinel"
  enforcement_level = "advisory"
}

policy "inspector__inspector-ec2-scan-enabled" {
  source            = "./policies-sentinel/inspector__inspector-ec2-scan-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "kinesis__kinesis-firehose-delivery-stream-encrypted" {
  source            = "./policies-sentinel/kinesis__kinesis-firehose-delivery-stream-encrypted.sentinel"
  enforcement_level = "advisory"
}

policy "kms__kms-restrict-iam-inline-policies-decrypt-all-kms-keys" {
  source            = "./policies-sentinel/kms__kms-restrict-iam-inline-policies-decrypt-all-kms-keys.sentinel"
  enforcement_level = "advisory"
}

policy "lambda__lambda-function-public-access-prohibited" {
  source            = "./policies-sentinel/lambda__lambda-function-public-access-prohibited.sentinel"
  enforcement_level = "advisory"
}

policy "macie__macie-status-should-be-enabled" {
  source            = "./policies-sentinel/macie__macie-status-should-be-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "mq__mq-auto-minor-version-upgrade-enabled" {
  source            = "./policies-sentinel/mq__mq-auto-minor-version-upgrade-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "msk__msk-connect-connector-encrypted" {
  source            = "./policies-sentinel/msk__msk-connect-connector-encrypted.sentinel"
  enforcement_level = "advisory"
}

policy "neptune__neptune-cluster-audit-logs-publishing-enabled" {
  source            = "./policies-sentinel/neptune__neptune-cluster-audit-logs-publishing-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "network-firewall__network-firewall-logging-enabled" {
  source            = "./policies-sentinel/network-firewall__network-firewall-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "opensearch__opensearch-access-control-enabled" {
  source            = "./policies-sentinel/opensearch__opensearch-access-control-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "rds__aurora-postgresql-db-clusters-should-publish-logs-to-cloudwatch-logs" {
  source            = "./policies-sentinel/rds__aurora-postgresql-db-clusters-should-publish-logs-to-cloudwatch-logs.sentinel"
  enforcement_level = "advisory"
}

policy "redshift__redshift-cluster-audit-logging-enabled" {
  source            = "./policies-sentinel/redshift__redshift-cluster-audit-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "redshiftserverless__redshift-serverless-namespaces-should-export-logs-to-cloudwatch-logs" {
  source            = "./policies-sentinel/redshiftserverless__redshift-serverless-namespaces-should-export-logs-to-cloudwatch-logs.sentinel"
  enforcement_level = "advisory"
}

policy "route53__route-53-public-hosted-zones-should-log-dns-queries" {
  source            = "./policies-sentinel/route53__route-53-public-hosted-zones-should-log-dns-queries.sentinel"
  enforcement_level = "advisory"
}

policy "s3-block-public-access-bucket-level" {
  source            = "./policies-sentinel/s3-block-public-access-bucket-level.sentinel"
  enforcement_level = "advisory"
}

policy "s3-require-ssl" {
  source            = "./policies-sentinel/s3-require-ssl.sentinel"
  enforcement_level = "advisory"
}

policy "s3__s3-access-point-block-public-access-enabled" {
  source            = "./policies-sentinel/s3__s3-access-point-block-public-access-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "sagemaker__sagemaker-endpoint-config-prod-instance-count-check" {
  source            = "./policies-sentinel/sagemaker__sagemaker-endpoint-config-prod-instance-count-check.sentinel"
  enforcement_level = "advisory"
}

policy "secretsmanager__secretsmanager-auto-rotation-enabled-check" {
  source            = "./policies-sentinel/secretsmanager__secretsmanager-auto-rotation-enabled-check.sentinel"
  enforcement_level = "advisory"
}

policy "servicecatalog__service-catalog-shared-within-organization" {
  source            = "./policies-sentinel/servicecatalog__service-catalog-shared-within-organization.sentinel"
  enforcement_level = "advisory"
}

policy "sns__sns-topic-access-policies-should-not-allow-public-access" {
  source            = "./policies-sentinel/sns__sns-topic-access-policies-should-not-allow-public-access.sentinel"
  enforcement_level = "advisory"
}

policy "sqs__sqs-queue-block-public-access" {
  source            = "./policies-sentinel/sqs__sqs-queue-block-public-access.sentinel"
  enforcement_level = "advisory"
}

policy "ssm__ssm-documents-should-not-be-public" {
  source            = "./policies-sentinel/ssm__ssm-documents-should-not-be-public.sentinel"
  enforcement_level = "advisory"
}

policy "stepfunction__step-functions-state-machine-logging-enabled" {
  source            = "./policies-sentinel/stepfunction__step-functions-state-machine-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "transfer__transfer-family-connectors-should-have-logging-enabled" {
  source            = "./policies-sentinel/transfer__transfer-family-connectors-should-have-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "waf__waf-classic-logging-enabled" {
  source            = "./policies-sentinel/waf__waf-classic-logging-enabled.sentinel"
  enforcement_level = "advisory"
}

policy "workspaces__workspaces-root-volumes-should-be-encrypted-at-rest" {
  source            = "./policies-sentinel/workspaces__workspaces-root-volumes-should-be-encrypted-at-rest.sentinel"
  enforcement_level = "advisory"
}
