control 'SV-233042' do
 title 'All audit records must identify what type of event has occurred within the
 container platform.'
 desc 'Within the container platform, audit data can be
 generated from any of the deployed container platform components. This audit data is
 important when there are issues, such as security incidents, that must be
 investigated. To make the audit data worthwhile for the investigation of events, it
 is necessary to know what type of event
 occurred.'
 desc 'check', 'Review the container platform configuration for audit event types.
 Ensure audit policy for event type is enabled. Verify records showing what type
 of event occurred are written to the log. Validate system documentation is
 current. If log data does not show the type of event, this is a finding.'
 desc 'fix', 'Configure the container platform to include the
 event type in the log data. Revise all applicable system documentation.'
 impact 0.5
 tag check_id: 'C-35978r601620_chk'
 tag severity: 'medium'
 tag severity_source: 'DISA SRG'
 tag gid: 'V-233042'
 tag rid: 'SV-233042r960891_rule'
 tag stig_id: 'SRG-APP-000095-CTR-000170'
 tag gtitle: 'SRG-APP-000095'
 tag fix_id: 'F-35946r600614_fix'
 tag 'documentable'
 tag cci: ['CCI-000130']
 tag nist: ['AU-3 a']
 tag ksi:  ['KSI-MLA-OSM']
 tag nist_r4: ['AU-3']
 tag implementation_status: 'implemented'

 # Durable, tamper-evident audit-record generation via account CloudTrail (cross-validates
 # cis-aws-foundations). CloudTrail's record schema carries event type/time/source/user.
 ok = audit_trail_compliant?
 impact 0.5
 describe 'CloudTrail audit-record generation (multi-region + log-file-validation + S3)' do
 subject { ok }
 it { is_expected.to be true }
 end
end
