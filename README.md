# Sandbox Gui

## Introduction
The Sandbox GUI ("gui") is a simple interface to test with the issueance and verification of various verifiable credentials. 

The sandbox relies on the backend agent to handle the 'heavy lifting' of marshalling the actual credentials and the issuance or verificiation in accordance with the OpenID4VCI and OpenID4VP protocols.

## Testing credentials
The gui will parse the contents of the tests directory to determine which tests need to be shown. And json file in the test directory will be considered as a logical section in the GUI, and the tests in the file will be grouped within that sections. 
Specific tests as defined in the section json will be presented in the GUI in the order of listing, from left to right (if screen with so allows).
Upon parsing the test and credentials definition, the gui will generate a API call towards the backend agent to create a request.

### Credential issuance
The API interface for issuance is generally formatted as following:
```
    "test_01a": {
        "name": "Academic Base Credential",
        "description": "This VC contains an Academic Base Credential for user Sharon. It will make use of a PIN",
        "type": "issuer",
        "flow": "pre_authorized_code",
        "credential": "sharon.json",
        "options": {
            "tx_code": true
        }
    },
```

| parameter | description |
|-----|-----|
| identifier | A unique lowercase string for this test within the test file |
| name | A user friendly name of the test |
| description | A description of the test |
| type | issuer or verifier |
| flow | only for issuance, either pre_authorized_code or authorization_code_flow (not yet supported) |
| credential | The credential to use, as found in the credentials directory  |
| options | only for issuance: tx_code: true/false to request the use of a pin, revoke: true/false to immediately upon issuance revoke the credential |

### Credential verification
The API interface for verification is formatted as following:

```
    {
        "type": "ABC"
    }
```
As shown for a verification flow the API only needs to learn which credential type needs to be verified.

### Credentials
Within the tests directory, the credentials directory holds the definitions of the credentials that are part of the tests. This way various tests may reuse certain credentials.
Three credential types are currently supported:
* GenericCredential
* PID
* ABC

Credential specific behaviour may be signalled in the credential by including key/value pairs starting with an "_", like "_ttl" which defines the expiration 

#### GenericCredential
The GenericCredential credential type allows for the issuance of a verifiable credential containing arbitrairy claims, as long as it can be represented as a set key value pairs. 
For example:
```
{
    "type": "GenericCredential",
    "claims": {
        "voPersonID": "0126789acdef014567@sram.surf.nl",
        "voperson_external_id": "05c028f81622d62987cbf74ea8fd0fb7ab86d45c980145515acef36162cb6988@uvh.nl",
        "ssh_public_key": "AAAAC3NzaC1lZDI1NTE5AAAAIBXRCFBt8gWg+V49eKdA+pocxGyZDzmMbQWfKaGPbdll cl@DroseraCapensis ",
        "voperson_external_affiliation": "faculty@uvh.nl, member@uvh.nl",
        "eduPersonAssurance": "https://refeds.org/assurance, https://refeds.org/assurance/profile/cappuccino, https://refeds.org/assurance/ID/unique, https://refeds.org/assurance/IAP/medium, https://refeds.org/assurance/IAP/local-enterprise, https://refeds.org/assurance/ATP/ePA-1m",
        "eduPersonEntitlement": "urn:mace:surf.nl:sram:group:galactic_senate:presidium, urn:mace:surf.nl:sram:group:galactic_senate:presidium:admins, urn:mace:surf.nl:sram:label:uniharderwijk:demo:id_123456",
        "_ttl": "62208000"
    }
}
```

#### PID
The PID credential type mimics the EUDIW PID credential:

```
{
    "type": "PID",
    "claims": {
        "_ttl": ["315569260"],
        "given_name": ["Martin"],
        "family_name": ["J\u00f8rgensen"],
        "birth_date": "07-07-1979",
        "family_name_birth": ["J\u00f8rgensen"],
        "given_name_birth": ["Martin"],
        "birth_place": ["Nieuwdorp The Netherlands"],
        "sex": [1],
        "nationality": ["NL"],
        "expiry_date": ["26-11-2027"],
        "issuance_date": ["15-06-2020"],
        "issuing_authority": ["SURF PBA"],
        "issuing_country": ["NL"],
        "age_in_years": [""],
        "age_birth_year": ["1979"],
        "birth_country": ["NL"],
        "birth_city": ["Nieuwdorp"],
        "resident_address": ["Bijleveldkade 77 4455TX The Netherlands"],
        "resident_country": ["The Netherlands"],
        "resident_city": ["Nieuwdorp"],
        "resident_postal_code": ["4455TX"],
        "resident_street": ["Bijleveldkade"],
        "resident_house_number": ["77"],
        "personal_administrative_number": ["106800403"],
        "age_over_18": [1],
        "age_over_13": [1],
        "portrait": [""],
        "document_number": ["PBA1068004"],
        "issuing_jurisdiction": ["NL"]
    }
}
```

#### ABC
The Academic Base Credential is a credential which provides a set of basic claims representing a user identity as used in academic IAM. It conform roughly to the attribute bundel used in the REFEFDs Personalized entity category.

```
    "type": "AcademicBaseCredential",
    "claims": {
        "_ttl": ["31104000"],
        "sub": ["43e27e05-a688-41df-ab1e-b74271fe02c6"],
        "eduperson_unique_id": ["43e27e05-a688-41df-ab1e-b74271fe02c6"],
        "given_name": ["Sharon"],
        "family_name": ["Hankins"],
        "name": ["Sharon Hankins"],
        "schac_home_organisation": ["UvH.nl"],
        "email": ["eduwallet.test+shankins.uvh@gmail.com"],
        "eduperson_affiliation": [
            "student",
            "member"
        ],
        "eduperson_scoped_affiliation": [
            "student@uvh.nl",
            "member@uvh.nl"
        ],
        "eduperson_entitlement": [
            "urn:mace:dir:entitlement:common-lib-terms-example"
        ],
        "eduperson_assurance": [
            "https://refeds.org/assurance"
        ]
    }
```

