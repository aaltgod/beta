import grpc
from concurrent import futures
import time
import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
import request_pb2
import request_pb2_grpc

class EchoService(request_pb2_grpc.EchoServiceServicer):
    def Echo(self, request, context):
        print(f"Received flag: {request.flag}")
        
        response = request_pb2.Response()
        response.flag = request.flag
        return response

def serve():
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
    request_pb2_grpc.add_EchoServiceServicer_to_server(EchoService(), server)
    server.add_insecure_port('[::]:50051')
    server.start()
    print("gRPC server is running on port 50051...")
    try:
        while True:
            time.sleep(86400)
    except KeyboardInterrupt:
        server.stop(0)

if __name__ == '__main__':
    serve()
