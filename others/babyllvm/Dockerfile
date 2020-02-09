FROM ubuntu:18.04

# Setup environ
ENV user babyllvm
ENV prob_port 7777

# Install packages
RUN apt-get update
RUN apt-get install -y socat python3 python3-pip
RUN python3 -m pip install llvmlite

# Change permission
RUN chmod 1733 /tmp /var/tmp /dev/shm

# Additional configuration
RUN adduser $user
ADD ./binary_flag/main.py /home/$user/main.py
ADD ./binary_flag/runtime.so /home/$user/runtime.so
ADD ./binary_flag/flag /home/$user/flag

RUN chown -R root:root /home/$user/
RUN chown root:$user /home/$user/main.py
RUN chown root:$user /home/$user/flag

RUN chmod 2755 /home/$user/main.py
RUN chmod 440 /home/$user/flag

# final
CMD socat -T 5 TCP-LISTEN:$prob_port,reuseaddr,fork EXEC:/home/$user/main.py
USER $user
EXPOSE $prob_port
