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
bash dir_creator.sh

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO_NO_ORDERING"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c vertigo_no_ordering -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET deflection_and_ordering.ini
do_extract dctcp_vertigo_no_ordering
mkdir logs/dctcp_vertigo_no_ordering
cp results/*.out logs/dctcp_vertigo_no_ordering/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO_NO_SCHEDULING"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c vertigo_no_scheduling -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET deflection_and_ordering.ini
do_extract dctcp_vertigo_no_scheduling
mkdir logs/dctcp_vertigo_no_scheduling
cp results/*.out logs/dctcp_vertigo_no_scheduling/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO_NO_DEFLECTION"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c vertigo_no_deflection -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET deflection_and_ordering.ini
do_extract dctcp_vertigo_no_deflection
mkdir logs/dctcp_vertigo_no_deflection
cp results/*.out logs/dctcp_vertigo_no_deflection/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c vertigo -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET deflection_and_ordering.ini
do_extract dctcp_vertigo
mkdir logs/dctcp_vertigo
cp results/*.out logs/dctcp_vertigo/

# move the extracted results
echo "Moving the extracted results to results_50_bg_dqps"
rm -rf results_deflection_and_ordering
mv extracted_results results_deflection_and_ordering