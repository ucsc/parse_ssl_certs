parse_ssl_certs
===============

Parsing nmap and nexpose ssl files

Very simply this code will look through either NMAP or Nexpose output to identify all information relating to a certificate.

The code in its current state is deliquite as it was done as a hackjob. 

The script will ask the user to determine wether the output came from NMAP or NEXPOSE.

Nmap Assumption: 
```
--privileged --script=ssl-cert -Pn -p80,443,445,465,587,990,993,3389,5900,8080,8081, 8443,8834,9443,10443 -T4 -oA 20140106\_nmap\_ssl\_scan --open 128.114.0.0/16
```

Nexpose Assumption (SQL Call): 

```
WITH  
  dim_asset_service_configuration_name_value AS (  
    SELECT asset_id, name || ':' || value AS name_value  
    FROM dim_asset_service_configuration dasc  
    WHERE name like 'ssl.%'  
  ),  
  dim_asset_service_configuration_name_values AS (  
    SELECT asset_id,   
      array_to_string(array_agg(DISTINCT name_value ORDER BY name_value), ' | ') AS name_values   
    FROM dim_asset_service_configuration_name_value  
    GROUP BY asset_id  
  )  
SELECT da.ip_address, ds.name as sitename, dasc.name_values  
FROM dim_asset_service_configuration_name_values dasc  
join dim_asset da using(asset_id)  
join dim_site_asset dsa using (asset_id)  
join dim_site ds using (site_id)
```

The script will look for the following attributes and add them into the resultant file: results.csv

NEXPOSE:

* IP
* ~~HOSTNAME~~
* ALGORITHM
* SIZE (BITS)
* VALID AFTER
* VALID BEFORE
* TRURST ISSUE (CHAINERROR)
* ISSUER
  * ORGNAME
  * ORGUNIT
  * CITY
  * STATE
  * COUNTRY
* SELF SIGNED
* VALID SIGNATURE

NMAP:

* IP
* HOSTNAME
* ALGORITHM
* SIZE (BITS)
* VALID AFTER
* VALID BEFORE
* TRURST ISSUE (CHAINERROR)
* ISSUER
  * ORGNAME
  * ORGUNIT
  * CITY
  * STATE
  * COUNTRY
* SELF SIGNED
* VALID SIGNATURE
