control 'SV-233063' do
  title 'The container platform must use FIPS validated cryptographic mechanisms to
                protect the integrity of log information.'
  desc 'To fully investigate an incident and to have trust in
                the audit data that is generated, it is important to put in place data protections.
                Without integrity protections, unauthorized changes may be made to the audit files
                and reliable forensic analysis and discovery of the source of malicious system
                activity may be degraded. Although digital signatures are one example of protecting
                integrity, this control is not intended to cause a new cryptographic hash to be
                generated every time a record is added to a log file. Integrity protections can also
                be implemented by using cryptographic techniques for security function isolation and
                file system protections to protect against unauthorized
                changes.'
  desc 'check', 'Review the container platform configuration to determine if
                    FIPS-validated cryptographic mechanisms are being used to protect the integrity
                    of log information. If FIPS-validated cryptographic mechanisms are not being
                    used to protect the integrity of log information, this is a finding.'
  desc 'fix', 'Configure the container platform to use
                FIPS-validated cryptographic mechanisms to protect the integrity of log information.'
  impact 0.5
  tag check_id: 'C-35999r601673_chk'
  tag severity: 'medium'
  tag gid: 'V-233063'
  tag rid: 'SV-233063r960951_rule'
  tag stig_id: 'SRG-APP-000126-CTR-000275'
  tag gtitle: 'SRG-APP-000126'
  tag fix_id: 'F-35967r600677_fix'
  tag 'documentable'
  tag cci: ['CCI-001350']
  tag nist: ['AU-9 (3)']
  tag implementation_status: 'inherited'
  tag inherited_from: 'aws-shared-responsibility'

  # AWS-managed container-platform layer (runtime/host/control-plane/crypto-module/audit-
  # infra). Evidence = the leveraged AWS FedRAMP/DoD authorization manifest; Skip (not a
  # vacuous pass) until the consumer configures leveraged_evidence_base/inherited_evidence_uri.
  ev = input('inherited_evidence_uri', value: '')
  ev = attestation_uri(:leveraged, 'aws-container-platform-authorization', ext: 'json') if ev.to_s.empty?
  max_age = input('leveraged_evidence_max_age_days', value: 365)
  impact 0.5
  if ev.to_s.empty?
    describe 'AWS-inherited authorization evidence' do
      skip 'inherited-from-aws: AWS-managed layer; set leveraged_evidence_base / inherited_evidence_uri to the AWS FedRAMP/DoD authorization manifest, or supply a SAF attestation.'
    end
  else
    doc = document_attestation(ev, max_age_days: max_age)
    describe "AWS authorization evidence (#{ev})" do
      it('exists')  { expect(doc.exists?).to eq(true) }
      it('current') { expect(doc.current?(max_age)).to eq(true) }
    end
  end
end
