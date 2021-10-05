#!/bin/bash

    
for (( i = 1; i<= ($1 - 1); i++ ))
do  
    ./main
    echo "Do $i times"

done