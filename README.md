# Splunk
Useful Splunk Searches

## How to correlate parent and child processes from 4688 Eventlog
Using streamstats to show child processes being spawned within 60 seconds after the parent instance. (Not 100% Coverage).
To increase/decrease this time span, simple tweak the time_window parameter below:

EventCode=4688
| table _time ComputerName New_Process_Name New_Process_ID Creator_Process_ID
| eval proc_name_id_all=New_Process_Name."#mysep#".New_Process_ID
| sort 0 + _time
| streamstats time_window=60s values(proc_name_id_all) AS proc_name_id_all by ComputerName
| eval parent=mvfind(proc_name_id_all, "#mysep#".Creator_Process_ID."$")
| eval parent=replace(mvindex(proc_name_id_all,parent), "^(.+)#mysep#.+$", "\1")


## Admin account tracking via Eventlog ID 4688 (New Process)
|index=X sourcetype=Y EventCode=4688 Token_Elevation_Type="*(3)"
Too do: Table this off and clean out the noise.

Hint for the Hunt
Monitor for Token Elevation Type with value TokenElevationTypeDefault (2) on standard workstations, when Subject\Security ID lists a 
real user account, for example when Account Name doesn’t contain the $ symbol. This means that a user ran a program using administrative 
privileges.

## McAfee ePO Critical/High events
index=* sourcetype=* (severity=critical OR severity=high) | stats values(event_description) AS desc, values(signature) AS signature, values(file_name) AS file_path, count AS result BY dest | eval dd="index=main sourcetype=mcafee:epo (severity=critical OR severity=high) dest=".dest

## Listing indexes and their sourcetypes
| eventcount summarize=false index=* index=_* | dedup index | fields index 
  | map maxsearches=100 search="|metadata type=sourcetypes index=\"$index$\" | eval index=\"$index$\""
  | fields index sourcetype
  
 Using TSTATS is actually WAY better for this.
 | tstats count WHERE index=* OR sourcetype=* by index,sourcetype | stats values(sourcetype) AS sourcetypes by index

## Finding cleartext passwords
index='' sourcetype=stream:http form_data=*username*passwd* | table _time form_data

...with regex and extracting only the password
index='' sourcetype=stream:http http_method=POST | rex field=form_data "passwd=(?<userpassword>\w+)" |search userpassword=* | reverse | table userpassword src_ip

## Using the reverse command
| reverse

## Using the stats command
| stats count by 'insert field here'

### CREDIT TO
inodee/threathunting-spl;spl.ninja;MuS
