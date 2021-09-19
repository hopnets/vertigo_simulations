echo "Downloading dist files..."

mkdir distributions

bash dist_downloader_files/dist_downloader_large_fattree_cache_bg_web_incast.sh < dist_downloader_files/dist_file_names_large_fattree_cache_bg_web_incast.csv

bash dist_downloader_files/dist_downloader_large_leaf_spine_web_incast.sh < dist_downloader_files/dist_file_names_large_leaf_spine_web_incast.csv

bash dist_downloader_files/dist_downloader_parallel_large_cache_bg_web_incast_extra_files.sh < dist_downloader_files/parallel_large_cache_bg_web_incast_extra_files.csv

echo "Extracting dist files!"

bunzip2 -vf ./distributions/*.bz2

echo "Done!"