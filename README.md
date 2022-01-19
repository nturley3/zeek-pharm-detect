# HTTP Pharmacy Reference Detection

## Purpose

This Zeek module detects the presence of pharmaceutical references on a website.
Often a threat actor will compromise or deface a website (typically a CMS site such
as Wordpress) to deploy links or content for pharmaceuticals.
The module will also extract sample payload from the site allowing quick
review by security analysts. 

NOTE: This script has the potential for lots of false positives, but can be used as an example on how to detect specific strings or data in HTTP payloads. It is not intended for heavy production environments without modifications. 

## Installation/Upgrade

This is easiest to install through the Zeek package manager:

	zkg refresh
	zkg install https://github.com/nturley3/zeek-pharm-detect

If you need to upgrade the package:

	zkg refresh
	zkg upgrade https://github.com/nturley3/zeek-pharm-detect

See the [Zeek Package Manager Docs](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.

## Configuration

No additional Zeek configuration is necessary for this package.

## Generated Outputs

The script generates a new notice log:

| Notice | msg field | sub field |  Description |
| ----- | ----- | ----- | ----- |
 HTTPDetectPharm::Found | HTTP payload of website contains references to pharmacy info - Response: | Excerpt of Payload | Identifies when pharmaceutical references common to compromised websites are found in HTTP traffic. |

## Usage

A security analyst could examine the excerpt in the "sub" field of the generated notice log to see if the content relates to a legitimate pharmaceutical reference or not.
If the excerpt looks like it displays advertisements, sales, or links to pharmaceutical, it is more likely a compromised website.
This can catch legitimate references as well if an organization's websites share information about pharmaceuticals such as in the case of medical research or other health website.

Type: Alert, Threat Hunting