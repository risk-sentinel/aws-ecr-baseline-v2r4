# encoding: UTF-8
#
# ECR scope helpers — resolve which repositories a control assesses. Included into
# every control via ::Inspec::Rule.include (the leading :: is required under InSpec 7;
# a bare Inspec::Rule.include raises uninitialized-constant at exec).
#
# Default scope is ACCOUNT-WIDE (every ECR repository), minus an exclusion list — most
# organizations have more than one registry, so the profile enumerates all and scores
# each, rather than requiring an allowlist. `excluded_repositories` drops specific repos
# from scoring (e.g. third-party / archived registries). `assessed_repositories`, if
# set, narrows to an explicit allowlist first; exclusions always apply on top.

module EcrScopeHelpers
  def ecr_repos_in_scope
    all      = aws_ecr_repositories.repository_names
    allow    = clean_list("assessed_repositories")
    base     = allow.empty? ? all : (all & allow)
    excluded = clean_list("excluded_repositories")
    base - excluded
  end

  def excluded_repositories_list
    clean_list("excluded_repositories")
  end

  private

  def clean_list(name)
    Array(input(name, value: [])).map(&:to_s).reject(&:empty?)
  end

  # AUDIT: a durable, tamper-evident account CloudTrail (multi-region + log-file-
  # validation + S3) = the mechanism that generates audit records for all API events.
  def audit_trail_compliant?
    Array(aws_cloudtrail_trails.names).any? do |n|
      t = aws_cloudtrail_trail(trail_name: n)
      t.is_multi_region_trail && t.log_file_validation_enabled && !t.s3_bucket_name.to_s.empty?
    end
  rescue StandardError
    false
  end
end

::Inspec::Rule.include(EcrScopeHelpers)
