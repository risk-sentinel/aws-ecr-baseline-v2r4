control 'SV-233105' do
  title 'The container platform must provide an audit reduction capability that supports
                on-demand reporting requirements.'
  desc "The ability to generate on-demand reports, including
                after the audit data has been subjected to audit reduction, greatly facilitates the
                organization's ability to generate incident reports as needed to better handle
                larger-scale or more complex security incidents. Audit reduction is a process that
                manipulates collected audit information and organizes such information in a summary
                format that is more meaningful to analysts. The report generation capability
                provided by the application must support on-demand (i.e., customizable, ad hoc, and
                as-needed) reports. This requirement is specific to applications with audit
                reduction capabilities; however, applications need to support on-demand audit review
                and
                analysis."
  desc 'check', 'Review the container platform configuration to determine if the
                    container platform is configured to provide an audit reduction capability that
                    supports on-demand reporting requirements. If the container platform is not
                    configured to support on-demand reporting requirements, this is a finding.'
  desc 'fix', 'Configure the container platform to support
                on-demand reporting requirements.'
  impact 0.5
  tag check_id: 'C-36041r601738_chk'
  tag severity: 'medium'
  tag gid: 'V-233105'
  tag rid: 'SV-233105r961056_rule'
  tag stig_id: 'SRG-APP-000181-CTR-000485'
  tag gtitle: 'SRG-APP-000181'
  tag fix_id: 'F-36009r600803_fix'
  tag 'documentable'
  tag cci: ['CCI-001876']
  tag nist: ['AU-7 a']
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
