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

# DCTCP RUNS
echo "\n\n-------------------------------------------"
echo "Running DCTCP_ECMP"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_ECMP -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract dctcp_ecmp

echo "\n\n-------------------------------------------"
echo "Running DCTCP_DRILL"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_DRILL -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract dctcp_drill

echo "\n\n-------------------------------------------"
echo "Running DCTCP_DIBS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_DIBS -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract dctcp_dibs

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VALINOR"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_V_SRPT_SCH_SRPT_ORD -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract dctcp_valinor

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VALINOR_LAS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_V_LAS_SCH_LAS_ORD -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract dctcp_valinor_las


# SWIFT RUNS
echo "\n\n-------------------------------------------"
echo "Running Swift_ECMP"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c Swift_ECMP -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract swfit_ecmp

echo "\n\n-------------------------------------------"
echo "Running Swift_DRILL"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c Swift_DRILL -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract swfit_drill

echo "\n\n-------------------------------------------"
echo "Running Swift_DIBS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c Swift_DIBS -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract swfit_dibs

echo "\n\n-------------------------------------------"
echo "Running Swift_VALINOR"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c Swift_Valinor -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract swfit_valinor


# TCP RUNS
echo "\n\n-------------------------------------------"
echo "Running TCP_ECMP"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_ECMP -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract tcp_ecmp

echo "\n\n-------------------------------------------"
echo "Running TCP_DRILL"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_DRILL -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract tcp_drill

echo "\n\n-------------------------------------------"
echo "Running TCP_DIBS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_DIBS -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract tcp_dibs

echo "\n\n-------------------------------------------"
echo "Running TCP_VALINOR"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_V_SRPT_SCH_SRPT_ORD -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract tcp_valinor

echo "\n\n-------------------------------------------"
echo "Running TCP_VALINOR_LAS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_V_LAS_SCH_LAS_ORD -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_50_bg_dscale.ini
do_extract tcp_valinor_las

# move the extracted results
echo "Moving the extracted results to results_50_bg_dscale"
rm -rf results_50_bg_dscale
mv extracted_results results_50_bg_dscale