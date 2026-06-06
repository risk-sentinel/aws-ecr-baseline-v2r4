control 'SV-233142' do
  title 'The container platform must use cryptographic mechanisms to protect the integrity
                of audit tools.'
  desc 'Protecting the integrity of the tools used for
                auditing purposes is a critical step to ensuring the integrity of audit data. Audit
                data includes all information (e.g., audit records, audit settings, and audit
                reports) needed to successfully audit information system activity. Audit tools
                include, but are not limited to, vendor provided and open source audit tools needed
                to successfully view and manipulate audit information system activity and records.
                Audit tools include custom queries and report generators. It is common for attackers
                to replace the audit tools or inject code into the existing tools with the purpose
                of providing the capability to hide or erase system activity from the audit logs. To
                address this risk, audit tools must be cryptographically signed in order to provide
                the capability to identify when the audit tools have been modified, manipulated, or
                replaced. An example is a checksum hash of the file or
                files.'
  desc 'check', 'Review the container platform configuration to determine if the
                    integrity of the audit tools is protected using cryptographic mechanisms. If
                    audit tools are not protected through cryptographic mechanisms, this is a
                    finding.'
  desc 'fix', 'Configure the container platform to use
                cryptographic mechanisms to protect the integrity of audit tools.'
  impact 0.5
  tag check_id: 'C-36078r600913_chk'
  tag severity: 'medium'
  tag gid: 'V-233142'
  tag rid: 'SV-233142r961206_rule'
  tag stig_id: 'SRG-APP-000290-CTR-000670'
  tag gtitle: 'SRG-APP-000290'
  tag fix_id: 'F-36046r600914_fix'
  tag 'documentable'
  tag cci: ['CCI-001496']
  tag nist: ['AU-9 (3)']
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
