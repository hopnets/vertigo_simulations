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
echo "Running DCTCP_VERTIGO_NO_BOOSTING"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c vertigo_no_boosting -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET boosting.ini
do_extract dctcp_vertigo_no_boosting
mkdir logs/dctcp_vertigo_no_boosting
cp results/*.out logs/dctcp_vertigo_no_boosting/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO_2_BOOSTING"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c vertigo_2_boosting -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET boosting.ini
do_extract dctcp_vertigo_2_boosting
mkdir logs/dctcp_vertigo_2_boosting
cp results/*.out logs/dctcp_vertigo_2_boosting/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO_4_BOOSTING"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c vertigo_4_boosting -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET boosting.ini
do_extract dctcp_vertigo_4_boosting
mkdir logs/dctcp_vertigo_4_boosting
cp results/*.out logs/dctcp_vertigo_4_boosting/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO_8_BOOSTING"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c vertigo_8_boosting -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET boosting.ini
do_extract dctcp_vertigo_8_boosting
mkdir logs/dctcp_vertigo_8_boosting
cp results/*.out logs/dctcp_vertigo_8_boosting/

# move the extracted results
echo "Moving the extracted results to results_50_bg_dqps"
rm -rf results_boosting
mv extracted_results results_boosting