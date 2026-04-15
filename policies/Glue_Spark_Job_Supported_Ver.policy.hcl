# Glue Spark Job Supported Version Policy
#
# This policy ensures that AWS Glue Spark jobs use only supported Glue versions.
# Converted from Sentinel policy: glue-spark-job-supported-version
#
# Resources checked:
# - aws_glue_job (glueetl job type only)
#
# Compliance reference:
# https://docs.aws.amazon.com/securityhub/latest/userguide/glue-controls.html#glue-4

policy {}

resource_policy "aws_glue_job" "supported_version" {

  enforcement_level = "advisory"
    locals {
        # Extract command block and job type
        command = core::try(attrs.command, [])
        job_type = core::length(local.command) > 0 ? core::try(local.command[0].name, "") : ""
        
        # Get glue_version (can be null or empty string)
        glue_version = core::try(attrs.glue_version, null)
        
        # Check if this is a glueetl job
        is_glueetl = local.job_type == "glueetl"
        
        # Minimum supported version as string for comparison
        minimum_supported_version = "3.0"
        
        # Valid version strings (3.0 and above)
        valid_versions = ["3.0", "4.0", "5.0"]
        
        # Version validation for glueetl jobs
        # If not glueetl, always pass
        # If glueetl and version is null or empty, fail
        # If glueetl and version < 3.0, fail
        version_valid = !local.is_glueetl ? true : (
            local.glue_version != null &&
            local.glue_version != "" ?
            core::contains(local.valid_versions, local.glue_version) : false
        )
        
        # Safe address for error messages
        resource_address = core::try(meta.address, "unknown")
        glue_version_display = local.glue_version != null ? local.glue_version : "not set"
    }
    
    enforce {
        condition = local.version_valid
        error_message = "AWS Glue Spark jobs must use supported Glue versions. Resource '${local.resource_address}' has glue_version='${local.glue_version_display}' for job_type='${local.job_type}'. For 'glueetl' jobs, glue_version must be set to ${local.minimum_supported_version} or higher. Refer to https://docs.aws.amazon.com/securityhub/latest/userguide/glue-controls.html#glue-4 for more details."
    }
}