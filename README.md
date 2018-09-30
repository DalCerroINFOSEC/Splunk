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

## Extracting Certain Verbage using rex
Here is an example query
index=* sourcetype=stream:http form_data=*username*passwd*
| rex field=form_data "passwd=(?<userpassword>\w+)"
  
As you can see from our search the idea is that we use the rex command to extract values from the form_data field and look for a string that starts with passwd= and then immediately capture all the “word characters”, that is 0-9 A-Z and _. When it reaches the end of those character matches and hits the "&" in the data returned, it will stop capturing values. The resulting values extracted are placed in a new field called "userpassword."
  
| table userpassword

## Using len to calculate length
index=* sourcetype=stream:http form_data=*username*passwd* | rex field=form_data "passwd=(?<userpassword>\w+)"
| eval lenpword=len(userpassword)

Once we have extracted the password values, we really only care about 6 character passwords because that is the length of the title of the song in the question. To calculate the length of the userpassword fields, we can use the eval command with the len function. Len is short for length. This eval command will create a field called lenpword in this case, that will give us a numeric value for each password string.

| table userpassword lenpword

## Using lookups example
index=botsv1 sourcetype=stream:http form_data=*username*passwd* | rex field=form_data "passwd=(?<userpassword>\w+)" | eval lenpword=len(userpassword) | search lenpword=6
  
Here is our initial search that returns all passwords with a length of 6 from our events.

| eval password=lower(userpassword)

In lookups, case matters, so we will convert those extracted passwords to lower case using the eval command and lower function.

| lookup coldplay.csv song as password OUTPUTNEW song

The lookup command compares the lookup value, in this case song from the coldplay.csv file, to the password value from the events. If we get a hit, output the song.

| search song=*

Search for any of the results that have a song value

| table song

PUTTING IT TOGETHER
index=botsv1 sourcetype=stream:http form_data=*username*passwd* | rex field=form_data "passwd=(?<userpassword>\w+)" | eval lenpword=len(userpassword) | search lenpword=6 | eval password=lower(userpassword) | lookup coldplay.csv song as password OUTPUTNEW song  | table song password
  
Run Search in New Tab

If we left out the | search song=*, we would get results back that included passwords extracted from events but did not have the song match and we would need to go through our list looking for matches. In this example, we output both the song from the lookup and the password from the event to illustrate this. To make the search tighter, we add that search string.


## Login with plaintext password and URI
index='' sourcetype=stream:http form_data=*username*passwd* dest_ip=192.168.250.70 src=40.80.148.42 | rex field=form_data "passwd=(?<userpassword>\w+)"| search userpassword=* | table _time uri userpassword

## Using Averages to find average password length
index='' sourcetype=stream:http http_method=POST | rex field=form_data "passwd=(?<userpassword>\w+)" | search userpassword=*
| eval mylen=len(userpassword)
| stats avg(mylen) AS avg_len_http
| eval avg_len_http=round(avg_len_http,0)

## Auditing clear text password used / from source / along with time
index='' sourcetype=stream:http | rex field=form_data "passwd=(?<userpassword>\w+)" | search userpassword=batman | table _time userpassword src
  
## Transaction command. This command will calculate the time between the first event specified and the last.
index='' sourcetype=stream:http  | rex field=form_data "passwd=(?<userpassword>\w+)" |search userpassword=batman
| transaction userpassword | table duration

## Stats with URI
index='' dest=192.168.250.70 sourcetype=stream:http status=200 | stats count by uri | sort - count

## Counting fields & Unique counts with splunk
index='' sourcetype=stream:http | fields src_ip  | stats count(src_ip)
index='' sourcetype=stream:http | fields src_ip  | stats dc(src_ip)

## View URLs visited along with counts and a percentage field
index='' src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114 | stats count by http.url | eventstats sum(count) as perc | eval percentage=round(count*100/perc,2) | fields - perc | sort - count

## FTG traffic
index='' sourcetype=fgt_utm "192.168.250.70" |stats count by src | eventstats sum(count) as perc | eval percentage=round(count*100/perc,2) | fields - perc | sort - count

## Find sourcetypes by user(or any other field)
index='' 'insert user' | stats count by sourcetype | eventstats sum(count) as perc | eval percentage=round(count*100/perc,2) | fields - perc | sort - count

## URI Data with IIS logs

index='' sourcetype=iis sc_status=200 | stats values(cs_uri_stem)

## Playing with RAW fields, extracting DNS name.

index='' answer=23.22.63.114 sourcetype=stream:dns  | stats values("name{}")

RAW LOG
{"endtime":"2016-08-10T22:06:21.440131Z","timestamp":"2016-08-10T22:06:21.440125Z","host_addr":["23.22.63.114","23.22.63.114"],"name":["prankglassinebracket.jumpingcrab.com","prankglassinebracket.jumpingcrab.com"],"reply_code":["NoError","NoError"],"response_time":[62480,62486],"transaction_id":55247,"ttl":[3599,32768,3599,32768],"bytes":162,"src_ip":"192.168.250.20","src_mac":"00:0C:29:C3:C4:00","src_port":54421,"bytes_in":0,"dest_ip":"8.8.8.8","dest_mac":"08:5B:0E:93:92:AF","dest_port":53,"bytes_out":162,"time_taken":6,"transport":"udp"}

### CREDIT TO
inodee/threathunting-spl;spl.ninja;MuS
