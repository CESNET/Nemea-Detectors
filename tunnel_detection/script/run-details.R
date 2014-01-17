# Script will generate graphs of detail inforamtion about DNS communication each IP addres separely from given datas.
# First argument is file with histogram data. 
# Second argument is output name. (pdf format)

# Read argument from command line 
args <- commandArgs(trailingOnly = TRUE)

# Print to pdf
pdf( args[2], width = 30, height = 10 )

con <- file(args[1],open="r")
linn <- readLines(con)
title <- linn[1]
#extract horizontal labels
x_labels <-unlist(strsplit(linn[2], split="\t"))
x_labels <- x_labels[-1]
x_labels <- c(x_labels)
#for each ip address
for (i in 3:length(linn)){
	#separate data
	data <-unlist(strsplit(linn[i], split="\t"))
	ip <- data[1]
	data <- data[-1]
	data <- as.numeric(data)
	max <- max(data)
	#create graph
	graph <- barplot(data, main = paste(title, " IP: ", ip) , ylab= "Count",xlab="Size", beside=TRUE,  las=2, ylim = c(0, max * 1.1), axes = FALSE)
	#set axis
	axis(1, at = graph, lab = x_labels, las=2)
	step <- round(max/1000/20)*1000
	if(step==0){
		step <- round(max/100/20)*100
		if(step==0){
			step <- round(max/10/20)*10
			if(step==0){
				step <- round(max/20)
				if(step==0)
					step=1;
			}
		}
	}
	axis(2, at = seq(0, max * 1.1, by = step), las=1)
	
}
close(con)
