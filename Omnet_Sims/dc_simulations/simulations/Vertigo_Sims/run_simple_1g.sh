#!/bin/bash


do_extract () {
    python3 ./extractor_shell_creator.py $1
    pushd ./results/
    bash extractor.sh
    popd
    sleep 5
}

rm -rf results

# create the directory to save extracted_results
bash ./dir_creator.sh

# DCTCP RUNS
echo "\n\n-------------------------------------------"
echo "Running DCTCP_ECMP"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_ECMP -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET simple_1Gbps.ini
do_extract dctcp_ecmp
mkdir logs/dctcp_ecmp_sample_1g
cp results/*.out logs/dctcp_ecmp_sample_1g/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_DRILL"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_DRILL -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET simple_1Gbps.ini
do_extract dctcp_drill
mkdir logs/dctcp_drill_sample_1g
cp results/*.out logs/dctcp_drill_sample_1g/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_DIBS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_DIBS -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET simple_1Gbps.ini
do_extract dctcp_dibs
mkdir logs/dctcp_dctcp_dibs_sample_1g
cp results/*.out logs/dctcp_dctcp_dibs_sample_1g/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_V_SRPT_SCH_SRPT_ORD -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET simple_1Gbps.ini
do_extract dctcp_vertigo
mkdir logs/dctcp_vertigo_sample_1g
cp results/*.out logs/dctcp_vertigo_sample_1g/

# move the extracted results
echo "Moving the extracted results to results_sample_1g"
rm -rf results_sample_1g
mv extracted_results results_sample_1g

# Processing the results
python3 simple_qct.py 
python3 simple_fct.py
