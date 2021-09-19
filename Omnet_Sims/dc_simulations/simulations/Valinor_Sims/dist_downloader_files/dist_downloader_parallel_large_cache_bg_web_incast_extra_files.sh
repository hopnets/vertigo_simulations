while read p; do
  wget http://52.179.18.182/parallel_large_cache_bg_web_incast_extra_files/$p -P ./distributions/
done 
