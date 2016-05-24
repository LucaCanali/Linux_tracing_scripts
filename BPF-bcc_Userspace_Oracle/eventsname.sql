--
-- eventsname.sql
--
-- This sqlplus script generates a sed script file to replace oracle wait event numbers with even names
-- intended to be used together the systemtap trace scripts
--
-- L.C. Aug 2014
--

set echo off pages 0 lines 200 feed off head off sqlblanklines off trimspool on trimout on

spool eventsname.sed

select 's/\<event#='||to_char(event#)||'\>/'||'event='||replace(name,'/','\/')||'/g' SED from v$event_name order by event# desc;

spool off
exit
