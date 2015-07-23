--
-- ksuse_find_offset.sql
--
-- Script to find the offsets of data files in the X$KSUSE data structure (segment array)
-- The output of this script have been used to build stap probes trace_oracle_events_12102 and trace_oracle_events_11204
-- Author: Luca.Canali@cern.ch, Aug 2014 
-- Thanks to @FritsHoolgand for the pointing this method out to me
--

select c.kqfconam FIELD_NAME, c.kqfcooff OFFSET from x$kqfco c, x$kqfta t
where t.indx = c.kqfcotab
and t.kqftanam='X$KSUSE'
and c.kqfconam in ('KSUSEOPC','KSUSEP1','KSUSEP2','KSUSEP3','KSUSETIM','KSUSESQH','KSUSETIM','KSUSENUM','KSUUDNAM','KSUSEOBJ')
order by c.kqfcooff;
