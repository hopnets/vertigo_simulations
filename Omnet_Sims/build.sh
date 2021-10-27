# make inet

coreNum=$(cat /proc/cpuinfo | grep processor | wc -l)
coreNum=$((coreNum))

echo "$coreNum hyper-threads used for building."

echo -e "-------------------------- make clean -C ./inet/ --------------------------"
make clean -C ./inet/

echo -e "\n\n-------------------------- make -C ./inet/ makefiles --------------------------"
make -C ./inet/ makefiles

echo -e "\n\n-------------------------- make -j $coreNum -C ./inet/ MODE=release all --------------------------"
make -j $coreNum -C ./inet/ MODE=release all



# make simulations/src

echo -e "\n\n-------------------------- make clean -C ./dc_simulations/ --------------------------"
make clean -C ./dc_simulations/

echo -e "\n\n-------------------------- make -C ./dc_simulations/ MODE=release all --------------------------"
make -j $coreNum -C ./dc_simulations/ MODE=release all

