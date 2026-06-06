control 'SV-233189' do
  title 'The container platform must enforce access restrictions and support auditing of
                the enforcement actions.'
  desc 'Auditing the enforcement of access restrictions
                against changes to the container platform helps identify attacks and provides
                forensic data for investigation for after-the-fact actions. Attempts to change
                configurations, components, or data maintained by a component (e.g., images in the
                registry, running containers in the runtime, or keys in the keystore) must be
                audited. Enforcement actions are the methods or mechanisms used to prevent
                unauthorized changes to configuration settings. Enforcement action methods may be as
                simple as denying access to a file based on the application of file permissions
                (access restriction). Audit items may consist of lists of actions blocked by access
                restrictions or changes identified after the
                fact.'
  desc 'check', 'Review container platform documentation and logs to determine if
                    enforcement actions used to restrict access associated with changes to the
                    container platform are logged. If these actions are not logged, this is a
                    finding.'
  desc 'fix', 'Configure the container platform to log the
                enforcement actions used to restrict access associated with changes.'
  impact 0.5
  tag check_id: 'C-36125r601054_chk'
  tag severity: 'medium'
  tag gid: 'V-233189'
  tag rid: 'SV-233189r981889_rule'
  tag stig_id: 'SRG-APP-000381-CTR-000905'
  tag gtitle: 'SRG-APP-000381'
  tag fix_id: 'F-36093r601055_fix'
  tag 'documentable'
  tag cci: ['CCI-003938']
  tag nist: ['CM-5 (1) (b)']
  tag implementation_status: 'inherited'
  tag inherited_from: 'aws-shared-responsibility'

  # AWS-managed: IAM identity internals / Fargate runtime / platform config (the cloud-provider authorization).
  ev = input('inherited_evidence_uri', value: '')
  ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
  max_age = input('leveraged_evidence_max_age_days', value: 365)
  impact 0.5
  if ev.to_s.empty?
    describe 'AWS-inherited authorization evidence' do
      skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base/inherited_evidence_uri to the cloud-provider authorization manifest, or supply a SAF attestation.'
    end
  else
    doc = document_attestation(ev, max_age_days: max_age)
    describe "AWS authorization evidence (#{ev})" do
      it('exists') { expect(doc.exists?).to eq(true) }
      it('current') { expect(doc.current?(max_age)).to eq(true) }
    end
  end
end
