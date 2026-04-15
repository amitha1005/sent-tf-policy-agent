provider "aws" {
  region = "us-east-1"
}

resource "aws_mskconnect_connector" "validation_test" {
  name = "validation-test-connector"
  kafkaconnect_version = "2.7.1"

  capacity {
    autoscaling {
      mcu_count        = 1
      min_worker_count = 1
      max_worker_count = 2
      scale_in_policy {
        cpu_utilization_percentage = 20
      }
      scale_out_policy {
        cpu_utilization_percentage = 80
      }
    }
  }

  connector_configuration = {
    "connector.class" = "com.example.MyConnector"
    "tasks.max"       = "2"
  }

  kafka_cluster {
    apache_kafka_cluster {
      bootstrap_servers = "localhost:9092"
      vpc {
        security_groups = ["sg-12345678"]
        subnets         = ["subnet-12345678", "subnet-87654321"]
      }
    }
  }

  kafka_cluster_client_authentication {
    authentication_type = "NONE"
  }

  kafka_cluster_encryption_in_transit {
    encryption_type = "TLS"
  }

  plugin {
    custom_plugin {
      arn      = "arn:aws:kafkaconnect:us-east-1:123456789012:custom-plugin/test-plugin/abc123"
      revision = 1
    }
  }

  service_execution_role_arn = "arn:aws:iam::123456789012:role/service-role/kafka-connect-role"
}