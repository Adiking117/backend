import { asyncHandler } from "../utils/asyncHandler.js";
import { ApiError } from "../utils/ApiError.js"
import { User } from "../models/user.models.js"
import { uploadOnCloudinary } from "../utils/cloudinary.js"
import { ApiResponse } from "../utils/ApiResponse.js";



const registerUser = asyncHandler( async (req,res)=>{
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
    // console.log(req.body)


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


    // check if user already exist - email,username unique
    const existedUser = await User.findOne({
        $or: [{ username },{ email }]
    })
    if(existedUser){
        throw new ApiError(409,"User Already exist")
    }
    // console.log(existedUser)

    
    // check for images , avatar
    // console.log(req.files)
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


    // create user object - create entry in db
    const user = await User.create({
        fullName,
        avatar:avatar.url,
        coverImage: coverImage?.url || "",
        email,
        password,
        username: username.toLowerCase()
    })


    // remove password and refresh token field from response   
    const createdUser = await User.findById(user._id).select(
        "-password -refreshToken"
    )


    // check for user creation - null , response came
    if(!createdUser){
        throw new ApiError(500,"Something went wrong while registering user")
    }


    // retrun response
    return res.status(201).json(
        new ApiResponse(200, createdUser , "User Registerd Successfully")
    )


})

export { registerUser }