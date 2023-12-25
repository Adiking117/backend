import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.models.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js";
import jwt from "jsonwebtoken";

const generateAccessAndRefreshTokens = async(userId)=>{
    try {

        const user = await User.findById(userId)
        const accessToken = user.generateAccessToken()
        const refreshToken = user.generateRefreshToken()

        user.refreshToken = refreshToken    // database save

        await user.save( { validateBeforeSave : false } )   // will not check for other entries
        return { accessToken,refreshToken }

    } catch (error) {
        throw new ApiError(500,"Something went wrong while generating access and refresh token")
    }
}


const registerUser = asyncHandler( async (req,res)=> {
    // get user details from frontend
    // validation - not empty
    // check if user already exist - email,username unique
    // check for images , check for avatar
    // upload them to cloudinary, avatar check
    // create user object - create entry in db
    // remove password and refresh token field from response
    // check for user creation - null , response came
    // retrun response

    // get user details from frontend
    const { fullName,email,username,password } = req.body
    // console.log(email);
    // console.log("req.body",req.body)


    // validation - not empty
    // if(fullName === ""){
    //     throw new ApiError(400,"FullName is required")
    // }
    if(
        [fullName,email,username,password].some((field)=>
        field?.trim()=== "")
    ){
        throw new ApiError(400,"All fields are required")
    }
    // if (![fullName, email, username, password].every(field => field?.trim())) {
    //     throw new ApiError(400, "All fields are required");
    // }
    


    // check if user already exist - email,username unique
    const existedUser = await User.findOne({
        $or: [{ username },{ email }]
    })
    if(existedUser){
        throw new ApiError(409,"User Already exist")
    }
    // console.log("exitsed user: ",existedUser)

    
    // check for images , avatar
    // console.log("req.files",req.files)
    const avatarLocalPath = req.files?.avatar[0]?.path;
    // const coverImageLocalPath = req.files?.coverImage[0]?.path;

    let coverImageLocalPath;
    if(req.files && Array.isArray(req.files.coverImage) 
    && req.files.coverImage.length>0){
        coverImageLocalPath = req.files.coverImage[0].path
    }
    
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar needed")
    }
    

    // upload them to cloudinary, avatar check it will take time
    const avatar = await uploadOnCloudinary(avatarLocalPath)
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)
    if(!avatar){
        throw new ApiError(400,"Avatar needed")
    }
    // console.log("avatar",avatar)
    // console.log("coverImage",coverImage)



    // create user object - create entry in db
    const user = await User.create({
        fullName,
        avatar:avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })
    // console.log("user",user)


    // remove password and refresh token field from response   
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )
    // console.log("createduser",createdUser);

    // check for user creation - null , response came
    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering user")
    }


    // retrun response
    return res.status(201).json(
        new ApiResponse(200, createdUser , "User Registerd Successfully")
    )

})


const loginUser = asyncHandler( async (req,res) => {
    // req.body -> data
    // username or email
    // find the user
    // password check
    // access and refresh token 
    // send cookies
    // return response


    // req.body -> data
    const {email,username,password}= req.body;


    // username or email
    if(!(username || email)){
        throw new ApiError(400,"Username or password required");
    }


    // find the user
    const user = await User.findOne({
        $or: [{ username },{ email }]
    })
    if(!user){
        throw new ApiError(404,"User does not exist");
    }


    // password check
    const isPasswordValid = await user.isPasswordCorrect(password)
    if(!isPasswordValid){
        throw new ApiError(401,"Invalid credentials");
    }

    
    // access and refresh token 
    const {accessToken,refreshToken} = await generateAccessAndRefreshTokens(user._id)

    

    // send cookies
    const loggedInUser = await User.findById(user._id).
    select("-password -refreshToken")

    const options = {       // modifible by server
        httpOnly:true,
        secure:true
    }


    // return response
    return res
    .status(200)
    .cookie("accessToken",accessToken,options)
    .cookie("refreshToken",refreshToken,options)
    .json(
        new ApiResponse(
            200,
            {
                // data
                user: loggedInUser ,accessToken,refreshToken
            },
            "User logged in Successfully"
        )
    )

})


const logoutUser = asyncHandler( async (req,res) => {
    // created a middleware auth.js
    // delete refresh token
    // cookies clear
    
    await User.findByIdAndUpdate(
        req.user._id,
        {
            $set: {
                refreshToken : undefined
            }
        },
        {
            new: true
        }
    )    

    const options = {       
        httpOnly:true,
        secure:true
    }

    return res
    .status(200)
    .clearCookie("accessToken",options)
    .clearCookie("refreshToken",options)
    .json(new ApiResponse(200,{},"User logged Out"))

})


const refreshAccessToken = asyncHandler( async (req,res) => {
    const incomingRefreshToken = req.cookies.refreshToken
    || req.body.refreshToken

    if(!incomingRefreshToken){
        throw new ApiError(401,"Unauthorized request")
    }

    try {
        const decodedToken = jwt.verify(
            incomingRefreshToken,
            process.env.REFRESH_TOKEN_SECRET
        )
    
        const user = await User.findById(decodedToken?._id)
    
        if(!user){
            throw new ApiError(401,"Invalid Refresh Token")
        }
    
        if(incomingRefreshToken !== user?.refreshToken){
            throw new ApiError(401,"Refresh Token is expired")
        }
    
        const options = {
            httpOnly:true,
            secure:true
        }
    
        const {accessToken, newRefreshToken } = await generateAccessAndRefreshTokens(user._id)
    
        return res
        .status(200)
        .cookie("accessToken",accessToken , options)
        .cookie("refreshToken",newRefreshToken , options)
        .json(
            new ApiResponse(
                200,
                {accessToken , refreshToken: newRefreshToken},
                "Access token refreshed"
            )
        )
    } catch (error) {
        throw ApiError(401,error?.message || "Invalid Refresh Token")
    }
})


const changeCurrentPassword = asyncHandler( async(req,res)=>{
    // take new and old password from user
    const {oldPassword , newPassword} = req.body

    // find the user in database from their id
    const user = await User.findById(req.user?._id)

    // check whether the old password is correct
    const isPasswordCorrect = await user.isPasswordCorrect(oldPassword)
    if(!isPasswordCorrect){
        throw new ApiError(400,"Invlaid old password")
    }

    // store the new password
    user.password = newPassword

    // save the updated details of user
    await user.save({ validateBeforeSave:false })

    // return response
    return res
    .status(200)
    .json(
        new ApiResponse(200,{},"Password change sucessfully")
    )
})


const getCurrentUser = asyncHandler( async(req,res)=>{
    return res
    .status(200)
    .json(200,req.user,"Current User fetched successfully")
})


const updateAccountDetails = asyncHandler( async(req,res)=>{
    const {fullName,email} = req.body
    if(!(fullName || email)){
        throw new ApiError(400,"All field are required")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set : {
                fullName: fullName,
                email : email
            }
        },
        {new:true}
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"Account details updated")
    )
})


const updateUserAvatar = asyncHandler( async(req,res)=>{
    const avatarLocalPath = req.file?.path
    if(!avatarLocalPath){
        throw new ApiError(400,"Avatar File misiing")
    }
    
    const avatar = await uploadOnCloudinary(avatarLocalPath)

    if(!avatar.url){
        throw new ApiError(400,"Error while uploading avatar")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                avatar : avatar.url
            }
        },
        { new : true }
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"Avatar updated successfully")
    )
})


const updateUserCoverImage = asyncHandler( async(req,res)=>{
    const coverImageLocalPath = req.file?.path
    if(!coverImageLocalPath){
        throw new ApiError(400,"CoverImage File misiing")
    }
    
    const coverImage = await uploadOnCloudinary(coverImageLocalPath)

    if(!coverImage.url){
        throw new ApiError(400,"Error while uploading coverImage")
    }

    const user = await User.findByIdAndUpdate(
        req.user?._id,
        {
            $set:{
                coverImage : coverImage.url
            }
        },
        { new : true }
    ).select("-password")

    return res
    .status(200)
    .json(
        new ApiResponse(200,user,"CoverImage updated successfully")
    )
})


const getUserChannelProfile = asyncHandler(async(req,res)=>{
    const {username} = req.params
    if(!username?.trim){
        throw new ApiError(400,"No username found")
    }

    const channel = await User.aggregate([
        {
            $match:{
                username:username?.toLowerCase()
            }
        },
        {   // counting subscribers
            $lookup:{
                from:"subscriptions",
                localField:"_id",
                foreignField:"channel",
                as:"subscribers"
            }
        },
        {   // counting channels which are subscibed
            $lookup:{
                from:"subscriptions",
                localField:"_id",
                foreignField:"subscriber",
                as:"subscribedTo"
            }
        },
        {
            $addFields:{
                subscribersCount:{
                    $size:"$subscribers"
                },
                channelsSubscribedToCount:{
                    $size:"$subscribedTo"
                },
                isSubscribed:{
                    $cond :{
                        if:{$in: [req.user?._id,"$subscribers.subscriber"]},
                        then:true,
                        else:false
                    }
                }
            }
        },
        {
            $project:{
                fullName: 1,
                username:1,
                subscribersCount:1,
                channelsSubscribedToCount:1,
                isSubscribed:1,
                avatar:1,
                coverImage:1,
                email:1
            }
        }
    ])
    
    console.log("channel", channel);

    if(!channel?.length){
        throw new ApiError(404,"No channel found")
    }

    return res
    .status(200)
    .json(
        new ApiResponse(200,channel[0],"User Channel fetched successfuly")
    )
})


const getWatchHistory = asyncHandler(async(req,res)=>{
    const user = await User.aggregate([
        {
            //$match: req.user._id
            $match : {
                _id:new mongoose.Types.ObjectId(req.user._id)
            }
        },
        {
            $lookup:{
                from:"videos",
                localField:"watchHistory",
                foreignField:"_id",
                as : "watchHistory",
                pipeline:[
                    {
                        $lookup:{
                            from:"users",
                            localField:"owner",
                            foreignField:"_id",
                            as: "owner",
                            pipeline:[
                                {
                                    $project:{
                                        fullName:1,
                                        username:1,
                                        avatar:1
                                    }
                                }
                            ]
                        }
                    },
                    {
                        $addFields:{
                            owner:{
                                $first:"$owner"
                            }
                        }
                    }
                ]
            }
        }
    ])

    console.log("USer ",user)

    return res
    .status(200)
    .json(
        new ApiResponse(200,user[0].watchHistory,"Watch History fetched")
    )
})

export  {   registerUser,
            loginUser,
            logoutUser,
            refreshAccessToken,
            changeCurrentPassword,
            getCurrentUser,
            updateAccountDetails,
            updateUserAvatar,
            updateUserCoverImage,
            getUserChannelProfile,
            getWatchHistory
        }