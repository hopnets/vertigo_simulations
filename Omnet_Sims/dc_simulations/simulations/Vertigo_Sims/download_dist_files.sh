echo "Downloading dist files..."

mkdir distributions

git clone https://sepehrabdous96@bitbucket.org/dc_group/vertigo_dist_files_conext21.git distributions

echo "Extracting dist files!"

unzip distributions/files.zip 
unzip distributions/large_fat_tree.zip
unzip distributions/parallel_large_cache_bg_web_incast_extra_files.zip

mv files/* distributions/
mv large_fat_tree/* distributions/
mv parallel_large_cache_bg_web_incast_extra_files/* distributions/

rm -rf files
rm -rf large_fat_tree
rm -rf parallel_large_cache_bg_web_incast_extra_files

bunzip2 -vf ./distributions/*.bz2

echo "Done!"