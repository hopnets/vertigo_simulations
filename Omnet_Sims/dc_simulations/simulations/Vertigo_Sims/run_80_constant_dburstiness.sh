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
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_ECMP -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract dctcp_ecmp
mkdir logs/dctcp_ecmp_80_constant_dburstiness
cp results/*.out logs/dctcp_ecmp_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_DRILL"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_DRILL -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract dctcp_drill
mkdir logs/dctcp_drill_80_constant_dburstiness
cp results/*.out logs/dctcp_drill_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_DIBS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_DIBS -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract dctcp_dibs
mkdir logs/dctcp_dctcp_dibs_80_constant_dburstiness
cp results/*.out logs/dctcp_dctcp_dibs_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_V_SRPT_SCH_SRPT_ORD -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract dctcp_vertigo
mkdir logs/dctcp_vertigo_80_constant_dburstiness
cp results/*.out logs/dctcp_vertigo_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running DCTCP_VERTIGO_LAS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c DCTCP_V_LAS_SCH_LAS_ORD -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract dctcp_vertigo_las
mkdir logs/dctcp_vertigo_las_80_constant_dburstiness
cp results/*.out logs/dctcp_vertigo_las_80_constant_dburstiness/


# SWIFT RUNS
echo "\n\n-------------------------------------------"
echo "Running Swift_ECMP"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c Swift_ECMP -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract swfit_ecmp
mkdir logs/swfit_ecmp_80_constant_dburstiness
cp results/*.out logs/swfit_ecmp_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running Swift_DRILL"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c Swift_DRILL -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract swfit_drill
mkdir logs/swfit_drill_80_constant_dburstiness
cp results/*.out logs/swfit_drill_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running Swift_DIBS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c Swift_DIBS -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract swfit_dibs
mkdir logs/swfit_dibs_80_constant_dburstiness
cp results/*.out logs/swfit_dibs_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running Swift_VERTIGO"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c Swift_Vertigo -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract swfit_vertigo
mkdir logs/swfit_vertigo_80_constant_dburstiness
cp results/*.out logs/swfit_vertigo_80_constant_dburstiness/


# TCP RUNS
echo "\n\n-------------------------------------------"
echo "Running TCP_ECMP"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_ECMP -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract tcp_ecmp
mkdir logs/tcp_ecmp_80_constant_dburstiness
cp results/*.out logs/tcp_ecmp_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running TCP_DRILL"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_DRILL -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract tcp_drill
mkdir logs/tcp_drill_80_constant_dburstiness
cp results/*.out logs/tcp_drill_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running TCP_DIBS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_DIBS -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract tcp_dibs
mkdir logs/tcp_dibs_80_constant_dburstiness
cp results/*.out logs/tcp_dibs_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running TCP_VERTIGO"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_V_SRPT_SCH_SRPT_ORD -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract tcp_vertigo
mkdir logs/tcp_vertigo_80_constant_dburstiness
cp results/*.out logs/tcp_vertigo_80_constant_dburstiness/

echo "\n\n-------------------------------------------"
echo "Running TCP_VERTIGO_LAS"
opp_runall -j50 ../../src/dc_simulations -m -u Cmdenv -c TCP_V_LAS_SCH_LAS_ORD -n ..:../../src:../../../inet/src:../../../inet/examples:../../../inet/tutorials:../../../inet/showcases --image-path=../../../inet/images -l ../../../inet/src/INET omnetpp_80_constant_dburstiness.ini
do_extract tcp_vertigo_las
mkdir logs/tcp_vertigo_las_80_constant_dburstiness
cp results/*.out logs/tcp_vertigo_las_80_constant_dburstiness/

# move the extracted results
echo "Moving the extracted results to results_80_constant_dburstiness"
rm -rf results_80_constant_dburstiness
mv extracted_results results_80_constant_dburstiness