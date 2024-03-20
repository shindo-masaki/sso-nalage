class AxiosRequest {
    static createRequest(CSRFToken){
        return axios.create({
            headers:{
                'X-CSRFToken': CSRFToken,
                'Content-Type': 'application/x-www-form-urlencoded'
            }
        })
    }

    static getRequest(requestPath, CSRFToken){
        const request = AxiosRequest.createRequest(CSRFToken)
        return request.get(requestPath)
    }

    static postRequest(requestPath, CSRFToken, requestData){
        const request = AxiosRequest.createRequest(CSRFToken)
        return request.post(requestPath, requestData)
    }
}
