echo "Downloading dist files..."

mkdir distributions

bash dist_downloader_files/1g_files.sh < dist_downloader_files/1g_files.csv

echo "Extracting dist files!"

bunzip2 -vf ./distributions/*.bz2

echo "Done!"