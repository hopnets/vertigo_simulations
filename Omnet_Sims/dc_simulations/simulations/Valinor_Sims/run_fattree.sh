#!/bin/bash


do_extract () {
    python3 ./extractor_shell_creator_fat_tree.py $1
    pushd ./results/
    bash extractor.sh
    popd
    sleep 5
}

rm -rf results

# create the directory to save extracted_results
bash dir_creator.sh

# DCTCP RUNS
echo "\n\n-------------------------------------------"
echo "Running DCTCP_ECMP"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_ECMP_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract dctcp_ecmp_fattree

echo "\n\n-------------------------------------------"
echo "Running DCTCP_DRILL"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_DRILL_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract dctcp_drill_fattree

echo "\n\n-------------------------------------------"
echo "Running DCTCP_DIBS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_DIBS_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract dctcp_dibs_fattree

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VALINOR"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_Valinor_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract dctcp_valinor_fattree

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VALINOR_LAS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_Valinor_LAS_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract dctcp_valinor_las_fattree


# TCP RUNS
echo "\n\n-------------------------------------------"
echo "Running TCP_ECMP"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_ECMP_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract tcp_ecmp_fattree

echo "\n\n-------------------------------------------"
echo "Running TCP_DRILL"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_DRILL_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract tcp_drill_fattree

echo "\n\n-------------------------------------------"
echo "Running TCP_DIBS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_DIBS_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract tcp_dibs_fattree

echo "\n\n-------------------------------------------"
echo "Running TCP_VALINOR"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_VALINOR_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract tcp_valinor_fattree

echo "\n\n-------------------------------------------"
echo "Running TCP_VALINOR_LAS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_VALINOR_LAS_fattree -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_fattree.ini
do_extract tcp_valinor_las_fattree

# move the extracted results
echo "Moving the extracted results to results_fattree"
rm -rf results_fattree
mv extracted_results results_fattree