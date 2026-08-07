# encoding: UTF-8
#
# aws_ecr_repository — posture of a single ECR repository: scan-on-push, image-tag
# mutability, encryption (KMS vs AES256), repository policy (parsed for public /
# cross-account access), and lifecycle-policy presence.
#
#   describe aws_ecr_repository(repository_name: 'app') do
#     it { should be_scan_on_push }
#     its('image_tag_mutability') { should cmp 'IMMUTABLE' }
#   end
#
# RepositoryPolicyNotFound / LifecyclePolicyNotFound are EXPECTED when unset and are
# rescued (not treated as resource errors) so the policy/lifecycle predicates report
# "absent" rather than failing the whole resource.

require "json"

class AwsEcrRepository < AwsResourceBase
  name "aws_ecr_repository"
  desc "Configuration + policy posture of a single ECR repository."
  example "
    describe aws_ecr_repository(repository_name: 'app') do
      it { should be_immutable }
    end
  "

  attr_reader :repository_name, :repository_arn, :registry_id,
              :image_tag_mutability, :encryption_type, :kms_key,
              :policy_text, :lifecycle_policy_text

  def initialize(opts = {})
    opts = { repository_name: opts } if opts.is_a?(String)
    super(opts)
    validate_parameters(required: %i[repository_name])
    @repository_name = opts[:repository_name]
    @exists = false

    catch_aws_errors do
      resp = @aws.ecr_client.describe_repositories(repository_names: [@repository_name])
      repo = resp.repositories.first
      next if repo.nil?

      @exists               = true
      @repository_arn       = repo.repository_arn
      @registry_id          = repo.registry_id
      @image_tag_mutability = repo.image_tag_mutability
      @scan_on_push         = repo.image_scanning_configuration&.scan_on_push == true
      enc                   = repo.encryption_configuration
      @encryption_type      = enc&.encryption_type
      @kms_key              = enc&.kms_key

      @policy_text = begin
        @aws.ecr_client.get_repository_policy(repository_name: @repository_name).policy_text
      rescue Aws::ECR::Errors::RepositoryPolicyNotFoundException
        nil
      end

      @lifecycle_policy_text = begin
        @aws.ecr_client.get_lifecycle_policy(repository_name: @repository_name).lifecycle_policy_text
      rescue Aws::ECR::Errors::LifecyclePolicyNotFoundException
        nil
      end
    end
  end

  def exists?
    @exists == true
  end

  def scan_on_push?
    @scan_on_push == true
  end

  def immutable?
    @image_tag_mutability.to_s == "IMMUTABLE"
  end

  def kms_encrypted?
    @encryption_type.to_s == "KMS"
  end

  def has_repository_policy?
    !@policy_text.to_s.empty?
  end

  def has_lifecycle_policy?
    !@lifecycle_policy_text.to_s.empty?
  end

  # True if the repository policy grants access to a principal outside this account
  # (a public "*" principal, or a cross-account IAM ARN). Used by the deny-all /
  # permit-by-exception + least-privilege registry controls.
  def policy_allows_external?
    return false if @policy_text.to_s.empty?
    doc = (JSON.parse(@policy_text) rescue nil)
    return false if doc.nil?
    Array(doc["Statement"]).any? do |st|
      next false unless st["Effect"] == "Allow"
      pr = st["Principal"]
      principals = pr.is_a?(Hash) ? Array(pr["AWS"]) : Array(pr)
      principals.map(&:to_s).any? do |p|
        p == "*" || (p =~ /arn:aws[^:]*:iam::(\d{12}):/ && Regexp.last_match(1) != @registry_id.to_s)
      end
    end
  end

  # Lazily-fetched image inventory (DescribeImages, paginated): per-image digest, tags,
  # scan status, and finding-severity counts. Fetched only when a control needs it.
  def images
    return @images if defined?(@images)
    @images = []
    @all_tags = []
    catch_aws_errors do
      next_token = nil
      loop do
        resp = @aws.ecr_client.describe_images(repository_name: @repository_name, next_token: next_token, max_results: 100)
        Array(resp.image_details).each do |d|
          # Every imageDetail's tags are collected FIRST — cosign pushes
          # signatures and attestations as separate TAGGED artifacts in this
          # same repository, and those tags are how a signature is detected
          # (see image_signed?). Skipping them here would discard the evidence.
          @all_tags.concat(Array(d.image_tags))

          # ...but a signature is not an image. artifactMediaType is non-null
          # ONLY for OCI artifacts that are not images (cosign signatures,
          # attestations, SBOMs). Including them made every signature report as
          # an unsigned image, and counted each as unscanned in the scan gate.
          next unless d.respond_to?(:artifact_media_type) && d.artifact_media_type.to_s.empty?

          summary = d.image_scan_findings_summary
          @images << {
            digest:          d.image_digest,
            tags:            Array(d.image_tags),
            scan_status:     d.image_scan_status&.status.to_s,
            severity_counts: (summary && summary.finding_severity_counts) || {},
          }
        end
        next_token = resp.next_token
        break if next_token.nil? || next_token.to_s.empty?
      end
    end
    @images
  end

  # Every tag in the repository, including those on non-image artifacts.
  def all_tags
    images # populates @all_tags as a side effect of the single DescribeImages pass
    @all_tags || []
  end

  # Image digests/tags that violate the scan gate: fail-closed — an image whose scan is
  # not COMPLETE counts as a violation (unscanned == unproven == non-compliant), as does
  # any image carrying findings above the tolerated severity ceiling.
  def scan_gate_violations(ceiling)
    rank = %w[INFORMATIONAL LOW MEDIUM HIGH CRITICAL]
    idx  = rank.index(ceiling.to_s.upcase) || rank.index("HIGH")
    disallowed = rank[(idx + 1)..] || []
    images.select do |im|
      next true unless im[:scan_status] == "COMPLETE" # fail-closed: unscanned == violation
      counts = im[:severity_counts] || {}
      disallowed.sum { |s| counts[s].to_i + counts[s.to_sym].to_i } > 0
    end.map { |im| im[:tags].first || im[:digest] }
  end

  SBOM_MEDIA = /spdx|cyclonedx|in-toto|\bsbom\b|bom/i.freeze

  # Images missing a signature and/or an SBOM referrer (supply-chain gaps). Fail-closed:
  # an unsigned image, or one without an attached SBOM, is a gap. Returns labels.
  def supply_chain_gaps
    images.map do |im|
      miss = []
      miss << "unsigned" unless image_signed?(im[:digest])
      miss << "no-SBOM"  unless image_has_sbom?(im[:digest])
      miss.empty? ? nil : "#{im[:tags].first || im[:digest][0, 16]}: #{miss.join('+')}"
    end.compact
  end

  # Images whose supply-chain state could NOT be determined — an API error, a
  # denied permission, a throttle. Deliberately separate from supply_chain_gaps:
  # "cannot determine" is not "non-compliant" (#11). Folding the two together
  # made an IAM denial indistinguishable from an unsigned image, so the control
  # was untrustworthy in both directions.
  def supply_chain_undetermined
    images.map do |im|
      reasons = []
      reasons << "signing: #{@signing_error}" if signing_undetermined?(im[:digest])
      reasons << "sbom: #{@sbom_error}"       if sbom_undetermined?(im[:digest])
      reasons.empty? ? nil : "#{im[:tags].first || im[:digest][0, 16]}: #{reasons.join('; ')}"
    end.compact
  end

  private

  # cosign's DEFAULT scheme: the signature for sha256:X is pushed as a separate
  # artifact tagged `sha256-X.sig` in the SAME repository. The referrers API is
  # opt-in, and AWS-native signing (Signer/Notation) is a different mechanism
  # again — so all three are checked and any one of them counts as signed.
  def cosign_tag_for(digest, suffix)
    "sha256-#{digest.to_s.delete_prefix('sha256:')}.#{suffix}"
  end

  def cosign_signed?(digest)
    all_tags.include?(cosign_tag_for(digest, "sig"))
  end

  def cosign_attested?(digest)
    %w[att sbom].any? { |s| all_tags.include?(cosign_tag_for(digest, s)) }
  end

  def native_signed?(digest)
    @signing_error = nil
    !Array(@aws.ecr_client.describe_image_signing_status(
      repository_name: @repository_name, image_id: { image_digest: digest }
    ).signing_statuses).empty?
  rescue StandardError => e
    @signing_error = e.class.name
    false
  end

  def image_signed?(digest)
    # Cheapest and most likely first: cosign tags come from the DescribeImages
    # pass already made, so this costs no API call and needs no extra grant.
    return true if cosign_signed?(digest)
    native_signed?(digest)
  end

  # True only when NO signature was found by any mechanism AND the one that
  # makes an API call errored — i.e. the answer is unknown rather than "no".
  def signing_undetermined?(digest)
    return false if cosign_signed?(digest)
    native_signed?(digest)
    !@signing_error.nil?
  end

  def referrer_sbom?(digest)
    @sbom_error = nil
    refs = []
    token = nil
    loop do
      resp = @aws.ecr_client.list_image_referrers(repository_name: @repository_name, subject_id: { image_digest: digest }, next_token: token)
      refs.concat(Array(resp.referrers))
      token = resp.next_token
      break if token.nil? || token.to_s.empty?
    end
    refs.any? { |r| %i[artifact_media_type artifact_type media_type].any? { |m| r.respond_to?(m) && r.public_send(m).to_s =~ SBOM_MEDIA } }
  rescue StandardError => e
    @sbom_error = e.class.name
    false
  end

  def image_has_sbom?(digest)
    return true if cosign_attested?(digest)
    referrer_sbom?(digest)
  end

  def sbom_undetermined?(digest)
    return false if cosign_attested?(digest)
    referrer_sbom?(digest)
    !@sbom_error.nil?
  end

  public

  def to_s
    "ECR Repository #{@repository_name}"
  end
end
