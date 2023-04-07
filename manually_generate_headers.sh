#!/bin/bash

GLISS_PATH=../gliss2/gliss2
TMS_PATH=../tms

$GLISS_PATH/gep/gliss-attr $TMS_PATH/tms.irg -o ./otawa_write.h -a otawa_write -p -t otawa_write.tpl -d ";" #-e otawa_uregs.nmp
$GLISS_PATH/gep/gliss-attr $TMS_PATH/tms.irg -o ./otawa_read.h -a otawa_read -p -t otawa_read.tpl -d ";" #-e otawa_uregs.nmp
