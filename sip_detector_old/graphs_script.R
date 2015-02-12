timestamp <- "2014_10_17_21_17_19-2014_10_18_04_02_31"
dir.create(paste0("graphs/", timestamp))

data <- read.csv(paste0("statistics/", timestamp, ".csv"), sep=",", head=TRUE)
print(names(data))

label <- ""
x <- ""

for(i in names(data)) {
  if (sum(is.na(data[[i]])) == length(data[[i]])) {
    next
  }
  switch(i,
    ip = {
      next
    },
    diff_src_2_ips_min_time = {
      label <- "Min. time interval of 2 diff. src IPs when given IP is dst"
      x <- "Time[s]"
    },
    diff_src_3_ips_min_time = {
      label <- "Min. time interval of 3 diff. src IPs when given IP is dst"
      x <- "Time[s]"
    },
    diff_src_4_ips_min_time = {
      label <- "Min. time interval of 4 diff. src IPs when given IP is dst"
      x <- "Time[s]"
    },
    diff_src_5_ips_min_time = {
      label <- "Min. time interval of 5 diff. src IPs when given IP is dst"
      x <- "Time[s]"
    },
    diff_dst_2_ips_min_time = {
      label <- "Min. time interval of 2 diff. dst IPs when given IP is src"
      x <- "Time[s]"
    },
    diff_dst_3_ips_min_time = {
      label <- "Min. time interval of 3 diff. dst IPs when given IP is src"
      x <- "Time[s]"
    },
    diff_dst_4_ips_min_time = {
      label <- "Min. time interval of 4 diff. dst IPs when given IP is src"
      x <- "Time[s]"
    },
    diff_dst_5_ips_min_time = {
      label <- "Min. time interval of 5 diff. dst IPs when given IP is src"
      x <- "Time[s]"
    },
    diff_as_src_from_2_names_min_time = {
      label <- "Min. time interval of 2 diff. src names when given IP is src"
      x <- "Time[s]"
    },
    diff_as_src_from_3_names_min_time = {
      label <- "Min. time interval of 3 diff. src names when given IP is src"
      x <- "Time[s]"
    },
    diff_as_src_from_4_names_min_time = {
      label <- "Min. time interval of 4 diff. src names when given IP is src"
      x <- "Time[s]"
    },
    diff_as_src_from_5_names_min_time = {
      label <- "Min. time interval of 5 diff. src names when given IP is src"
      x <- "Time[s]"
    },
    diff_as_src_to_2_names_min_time = {
      label <- "Min. time interval of 2 diff. dst names when given IP is src"
      x <- "Time[s]"
    },
    diff_as_src_to_3_names_min_time = {
      label <- "Min. time interval of 3 diff. dst names when given IP is src"
      x <- "Time[s]"
    },
    diff_as_src_to_4_names_min_time = {
      label <- "Min. time interval of 4 diff. dst names when given IP is src"
      x <- "Time[s]"
    },
    diff_as_src_to_5_names_min_time = {
      label <- "Min. time interval of 5 diff. dst names when given IP is src"
      x <- "Time[s]"
    },
    diff_as_dst_from_2_names_min_time = {
      label <- "Min. time interval of 2 diff. src names when given IP is dst"
      x <- "Time[s]"
    },
    diff_as_dst_from_3_names_min_time = {
      label <- "Min. time interval of 3 diff. src names when given IP is dst"
      x <- "Time[s]"
    },
    diff_as_dst_from_4_names_min_time = {
      label <- "Min. time interval of 4 diff. src names when given IP is dst"
      x <- "Time[s]"
    },
    diff_as_dst_from_5_names_min_time = {
      label <- "Min. time interval of 5 diff. src names when given IP is dst"
      x <- "Time[s]"
    },
    diff_as_dst_to_2_names_min_time = {
      label <- "Min. time interval of 2 diff. dst names when given IP is dst"
      x <- "Time[s]"
    },
    diff_as_dst_to_3_names_min_time = {
      label <- "Min. time interval of 3 diff. dst names when given IP is dst"
      x <- "Time[s]"
    },
    diff_as_dst_to_4_names_min_time = {
      label <- "Min. time interval of 4 diff. dst names when given IP is dst"
      x <- "Time[s]"
    },
    diff_as_dst_to_5_names_min_time = {
      label <- "Min. time interval of 5 diff. dst names when given IP is dst"
      x <- "Time[s]"
    },
    max_in_sim_calls = {
      label <- "Max. simultantenous inward (to given IP) calls"
      x <- "Count"
    },
    max_out_sim_calls = {
      label <- "Max. simultantenous outward (from given IP) calls"
      x <- "Count"
    },
    in_ring_count = {
      label <- "Number of inward (to given IP) calls which got to ringing state"
      x <- "Count"
    },
    in_ring_len_avg = {
      label <- "Avg. ringing length of inward (to given IP) calls"
      x <- "Time[s]"
    },
    in_ring_len_var = {
      label <- "Variance of ringing lengths of inward (to given IP) calls"
      x <- "Time[s*s]"
    },
    out_ring_count = {
      label <- "Number of outward calls which got to (from given IP) ringing state"
      x <- "Count"
    },
    out_ring_len_avg = {
      label <- "Avg. ringing length of outward (from given IP) calls"
      x <- "Time[s]"
    },
    out_ring_len_var = {
      label <- "Variance of ringing lengths of outward (from given IP) calls"
      x <- "Time[s*s]"
    },
    in_talk_count = {
      label <- "Number of inward (to given IP) calls which got to talking state"
      x <- "Count"
    },
    in_talk_len_avg = {
      label <- "Avg. talking length of inward (to given IP) calls"
      x <- "Time[s]"
    },
    in_talk_len_var = {
      label <- "Variance of talking lengths of inward (to given IP) calls"
      x <- "Time[s*s]"
    },
    out_talk_count = {
      label <- "Number of outward (from given IP) calls which got to talking state"
      x <- "Count"
    },
    out_talk_len_avg = {
      label <- "Avg. talking length of outward (from given IP) calls"
      x <- "Time[s]"
    },
    out_talk_len_var = {
      label <- "Variance of talking lengths of outward (from given IP) calls"
      x <- "Time[s*s]"
    },
    as_ep_from = {
      label <- "Number of sip transactions where given IP is src"
      x <- "Count"
    },
    as_ep_to = {
      label <- "Number of sip transactions where given IP is dst"
      x <- "Count"
    },
    as_proxy = {
      label <- "Number of sip transactions where given IP is proxy"
      x <- "Count"
    }
  )
  print(paste0(i, " ", label, " ", x))

  png(paste0("graphs/", timestamp, "/", i, "_hist.png"))
  # Consider only first 100% of values
  sorted <- sort(data[[i]])[1:length(data[[i]])*1.00]
  hist(sorted, main=label, xlab=x, breaks=20, xlim=c(0, max(sorted, na.rm = TRUE)))
  dev.off()
  
  png(paste0("graphs/", timestamp, "/", i, "_strip.png"))
  stripchart(data[[i]], pch=1, main=label, xlab=x)
  dev.off()

  png(paste0("graphs/", timestamp, "/", i, "_ecdf.png"))
  plot(ecdf(data[[i]]), verticals=TRUE, do.points = FALSE, main=label, xlab=x, ylab="Distribution")
  dev.off()
}
