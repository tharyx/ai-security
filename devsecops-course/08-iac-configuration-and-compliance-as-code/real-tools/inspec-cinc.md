# Real tools: InSpec and CINC Auditor

> Hedged guide. Verify at docs.chef.io/inspec and cinc.sh. **InSpec 6 and later require a license key**; **CINC Auditor** is the license-free community build and aims at full profile compatibility. The labs never need either (they use a YAML DSL that mirrors the concepts).

## Create and run a profile

```text
inspec init profile acme-baseline        # or: cinc-auditor init profile acme-baseline
inspec check acme-baseline               # structure and syntax check
inspec exec acme-baseline                # run locally
inspec exec acme-baseline -t ssh://ops@host.example --sudo --key-files ~/.ssh/ops_key
inspec exec acme-baseline --reporter cli json:results.json
```

Targets include SSH, WinRM, Docker containers (`-t docker://<id>`) and cloud APIs through resource packs (verify the current transport list).

## A control in Ruby (compare to the lab YAML)

```ruby
control 'os-01' do
  impact 0.9
  title 'Insecure legacy packages are not installed'
  describe package('telnet') do
    it { should_not be_installed }
  end
end
```

## Waivers

Use a waiver file to accept a known exception with an owner and an **expiration date**, instead of deleting the control.

## Licence decision

| Option | When it fits |
|---|---|
| InSpec (Progress Chef) | You already license Chef products or accept the key and terms |
| CINC Auditor | You want the open build and your profiles do not use vendor-only features |

Check both vendors' terms yourself. For the exam, say: "InSpec 6+ needs a license key; CINC Auditor is the license-free alternative."

## Baselines to start from

Community and vendor baselines exist for CIS and DISA STIG (for example the dev-sec project and MITRE SAF content). Review, test and pin them before use, and keep your own overlay profile for organisation-specific controls.
